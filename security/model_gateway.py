"""Private compatibility gateway for the three security frameworks."""
import asyncio
import hmac
import json
import os
import re
import sys
from pathlib import Path
from aiohttp import ClientSession, ClientTimeout, web

sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'control'))
from settings import MODEL, UPSTREAM_BASE, secret
from gemini_advisor import enrich_command_failure
KEY = secret('HARNESS_API_KEY')
EMBEDDER = None
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'control'))


async def pentagi_cached(request,data,job):
    from evidence import Evidence
    cache=Evidence()
    sandbox=next((match.group(1) for m in data.get('messages',[])
                  for match in [re.search(r'\[CIPHER_SANDBOX:([a-f0-9]{16})\]',str(m.get('content','')))] if match),job)
    environment='pentagi-docker:'+sandbox
    calls={}
    for message in data.get('messages',[]):
        for call in message.get('tool_calls',[]):
            if call.get('function',{}).get('name')=='terminal':
                try: calls[call['id']]=json.loads(call['function']['arguments'])
                except (ValueError,KeyError): pass
        if message.get('role')=='tool' and message.get('tool_call_id') in calls:
            args=calls[message['tool_call_id']]
            record=cache.find(job,args.get('input',''),environment,args.get('cwd',''))
            if record and record['status']=='pending':
                cache.finish(record['id'],message.get('content',''))
    streaming=data.pop('stream',False)
    data.pop('stream_options',None)
    terminal_observed=any(m.get('role')=='tool' and m.get('tool_call_id') in calls
                          for m in data.get('messages',[]))
    scoped_execution=any('[CIPHER_SCOPED_EXECUTION]' in str(m.get('content',''))
                         for m in data.get('messages',[]) if m.get('role')=='user')
    if scoped_execution and not terminal_observed:
        data['tool_choice']={'type':'function','function':{'name':'terminal'}}
    elif not any(m.get('role')=='tool' for m in data.get('messages',[])):
        data['tool_choice']='required'
    async with request.app['session'].post(UPSTREAM_BASE+'/chat/completions',
        json=data,headers={'Authorization':'Bearer '+KEY}) as response:
        result=await response.json()
        if response.status>=400:
            return web.json_response(result,status=response.status)
    if scoped_execution and not terminal_observed and not any(
            call.get('function',{}).get('name')=='terminal'
            for choice in result.get('choices',[]) for call in choice.get('message',{}).get('tool_calls',[])):
        from evidence import Evidence
        preserved=json.loads(Evidence().redact(json.dumps(result,ensure_ascii=False)))
        return web.json_response({'error':{
            'message':'PentAGI did not return the required terminal call. No execution was verified. '
                      'Unverified model response: '+json.dumps(preserved.get('choices',[]),ensure_ascii=False),
            'code':'missing_required_tool_call','execution_verified':False,
            'model_response':preserved}},status=502)
    for choice in result.get('choices',[]):
        message=choice['message']
        forwarded=[]
        cached=[]
        for call in message.get('tool_calls',[]):
            if call.get('function',{}).get('name')!='terminal':
                forwarded.append(call)
                continue
            try:
                args=json.loads(call['function']['arguments'])
                command=args['input']
                execute,record=cache.reserve(job,command,environment,args.get('cwd',''))
            except (ValueError,KeyError):
                forwarded.append(call)
                continue
            if execute:
                forwarded.append(call)
            else:
                cached.append(json.dumps(cache.reuse(record),ensure_ascii=False)[:9000])
        if cached:
            message['content']=(message.get('content') or '')+'\nRecorded command evidence (not a new execution):\n'+'\n'.join(cached)
            if forwarded:
                message['tool_calls']=forwarded
            else:
                message.pop('tool_calls',None)
                choice['finish_reason']='stop'
    if not streaming:
        return web.json_response(result)
    # Only coordinator-owned PentAGI calls are buffered for the command guard.
    # Return normal OpenAI SSE wire format to its native streaming client.
    response=web.StreamResponse(headers={'Content-Type':'text/event-stream','Cache-Control':'no-store'})
    await response.prepare(request)
    base={k:result[k] for k in ('id','created','model') if k in result}
    for choice in result.get('choices',[]):
        delta=dict(choice['message'])
        delta.pop('reasoning_content',None)
        for index,call in enumerate(delta.get('tool_calls',[])): call['index']=index
        for body in ({**base,'object':'chat.completion.chunk','choices':[{'index':choice['index'],'delta':delta,'finish_reason':None}]},
                     {**base,'object':'chat.completion.chunk','choices':[{'index':choice['index'],'delta':{},'finish_reason':choice['finish_reason']}]}):
            await response.write(('data: '+json.dumps(body)+'\n\n').encode())
    await response.write(b'data: [DONE]\n\n')
    await response.write_eof()
    return response


async def handler(request):
    if not hmac.compare_digest(request.headers.get('Authorization', ''), 'Bearer '+KEY):
        return web.json_response({'error': {'message': 'Unauthorized'}}, status=401)
    if request.path == '/v1/models':
        return web.json_response({'object':'list','data':[{'id':MODEL,'object':'model','owned_by':'local'}]})
    if request.path == '/v1/embeddings' and request.method == 'POST':
        data = await request.json()
        texts = data.get('input', [])
        if isinstance(texts, str):
            texts = [texts]
        if not texts or not all(isinstance(text, str) for text in texts) or len(texts)>128:
            return web.json_response({'error':{'message':'Expected 1–128 text inputs.'}},status=400)
        def embed():
            global EMBEDDER
            if EMBEDDER is None:
                from fastembed import TextEmbedding
                EMBEDDER = TextEmbedding('BAAI/bge-small-en-v1.5', threads=2)
            return [vector.tolist() for vector in EMBEDDER.embed(texts)]
        async with request.app['embedding_lock']:
            vectors = await asyncio.to_thread(embed)
        return web.json_response({'object':'list','model':'bge-small-en-v1.5','data':[
            {'object':'embedding','index':i,'embedding':v} for i,v in enumerate(vectors)],
            'usage':{'prompt_tokens':0,'total_tokens':0}})
    if request.path != '/v1/chat/completions' or request.method != 'POST':
        return web.json_response({'error':{'message':'Unsupported endpoint'}},status=404)
    data = await request.json()
    data['model'] = MODEL
    data['chat_template_kwargs'] = {'enable_thinking':False}
    data['max_tokens'] = min(max(1, int(data.pop('max_completion_tokens',data.get('max_tokens',2048)))),4096)
    data.setdefault('repeat_penalty',1.08)
    # The native Functions.disabled setting is not enforced by this PentAGI build.
    # Enforce analysis mode at the private provider boundary instead.
    if any('[CIPHER_ANALYSIS_ONLY]' in str(message.get('content',''))
           for message in data.get('messages',[]) if message.get('role')=='user'):
        data.pop('tools',None)
        data.pop('tool_choice',None)
        data.pop('parallel_tool_calls',None)
    data.pop('store',None)
    await enrich_command_failure(request.app['session'], data)
    marker=next((re.search(r'\[CIPHER_JOB:([a-f0-9]{24})\]',str(m.get('content','')))
                 for m in data.get('messages',[]) if re.search(r'\[CIPHER_JOB:([a-f0-9]{24})\]',str(m.get('content','')))),None)
    has_terminal=any(t.get('function',{}).get('name')=='terminal' for t in data.get('tools',[]))
    has_cai=any(t.get('function',{}).get('name')=='generic_linux_command' for t in data.get('tools',[]))
    if marker and has_cai and not any(m.get('role')=='tool' for m in data.get('messages',[])):
        data['tool_choice']='required'
    if marker and has_terminal:
        return await pentagi_cached(request,data,marker.group(1))
    async with request.app['session'].post(UPSTREAM_BASE+'/chat/completions',
            json=data,headers={'Authorization':'Bearer '+KEY}) as upstream:
        response = web.StreamResponse(status=upstream.status,headers={
            'Content-Type':upstream.headers.get('Content-Type','application/json'), 'Cache-Control':'no-store'})
        await response.prepare(request)
        async for chunk in upstream.content.iter_any():
            await response.write(chunk)
        await response.write_eof()
        return response


async def main():
    import logging
    logging.basicConfig(level=logging.INFO)
    app = web.Application(client_max_size=8*1024*1024)
    app['embedding_lock'] = asyncio.Lock()
    async with ClientSession(timeout=ClientTimeout(total=600)) as session:
        app['session'] = session
        app.router.add_route('*','/{path:.*}',handler)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner,'127.0.0.1',8082).start()
        # Only Docker's local bridge can reach the container-facing listener.
        docker_host=os.getenv('HARNESS_GATEWAY_DOCKER_HOST','')
        if docker_host: await web.TCPSite(runner,docker_host,8082).start()
        await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(main())
