"""Schema-constrained, snapshot-based line edits for the maintenance model."""
import hashlib


def proposal_schema(sources):
    return {'type':'object','additionalProperties':False,'required':[
        'title','reason','edits','regression_test_lines','vm_packages'], 'properties':{
        'title':{'type':'string'},'reason':{'type':'string'},
        'edits':{'type':'array','maxItems':4,'items':{
            'type':'object','additionalProperties':False,
            'required':['path','start_line','end_line','replacement_lines'],
            'properties':{'path':{'type':'string','enum':sorted(sources)},
                'start_line':{'type':'integer','minimum':1},
                'end_line':{'type':'integer','minimum':1},
                'replacement_lines':{'type':'array','items':{'type':'string'}}}}},
        'regression_test_lines':{'type':'array','items':{'type':'string'}},
        'vm_packages':{'type':'array','maxItems':8,'items':{'type':'string'}}}}


def normalize_proposal(raw,sources):
    """Apply numbered edits to the supplied snapshot; no model-supplied old text."""
    if not isinstance(raw,dict): raise ValueError('Proposal must be an object.')
    edits=raw.get('edits')
    if not isinstance(edits,list) or len(edits)>4: raise ValueError('Expected at most four edits.')
    test_lines=raw.get('regression_test_lines')
    if not isinstance(test_lines,list) or any(not isinstance(line,str) for line in test_lines):
        raise ValueError('Regression test must be a list of source lines.')
    grouped={}
    for edit in edits:
        path=edit.get('path')
        if path not in sources: raise ValueError('Edit path was not supplied: '+str(path))
        first,last=edit.get('start_line'),edit.get('end_line')
        lines=sources[path].splitlines(keepends=True)
        if type(first) is not int or type(last) is not int or not 1<=first<=last<=len(lines):
            raise ValueError('Invalid source line range for '+path)
        replacement=edit.get('replacement_lines')
        if not isinstance(replacement,list) or any(not isinstance(line,str) for line in replacement):
            raise ValueError('Replacement source must be strings.')
        # Some local models group several valid code lines into one JSON string.
        # Normalize the decoded source without guessing at malformed JSON escapes.
        replacement=[line for item in replacement for line in item.replace('\r\n','\n').replace('\r','\n').split('\n')]
        if sum(len(line) for line in replacement)>12000: raise ValueError('Replacement exceeds change budget.')
        grouped.setdefault(path,[]).append((first,last,replacement))
    normalized=[]
    for path,changes in grouped.items():
        lines=sources[path].splitlines(keepends=True)
        boundary=len(lines)+1
        for first,last,replacement in sorted(changes,reverse=True):
            if last>=boundary: raise ValueError('Overlapping edit ranges for '+path)
            boundary=first
            lines[first-1:last]=[line+'\n' for line in replacement]
        normalized.append({'path':path,'old':sources[path],'new':''.join(lines),
                           'source_sha256':hashlib.sha256(sources[path].encode()).hexdigest()})
    return {'title':raw.get('title','Harness improvement'),'reason':raw.get('reason',''),
            'edits':normalized,'regression_test':'\n'.join(test_lines)+'\n',
            'vm_packages':raw.get('vm_packages',[])}
