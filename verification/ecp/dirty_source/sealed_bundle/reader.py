"""Independent sealed dirty-bundle reader. Does not import writer or producer.

This verifies a caller-held FD's seals and internal bytes/claims only. It does
not authenticate source, origin, principal, lease, snapshot or directory.
Caller must keep the FD valid and exclude hostile concurrent FD manipulation.
"""
import base64
import bisect
import fcntl
import hashlib
import json
import os
import re
import stat
import struct

MAGIC=b'FFDBND1\0'
MAX_MANIFEST=8*1024*1024
MAX_BLOB=8*1024*1024
MAX_TOTAL=32*1024*1024
MAX_COMMIT=2*1024*1024
MAX_BLOBS=4096
MAX_ROWS=4096
MAX_PATH=4096
MAX_PATH_TOTAL=2*1024*1024
MAX_DEPTH=128
MAX_BUNDLE=48*1024*1024
MAX_NODES=100000
MAX_STR=8192
MAX_RAW_STRING=MAX_STR*12
REQUIRED_NAMES=('F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL')

class Invalid(ValueError):
    pass

def require(v,code):
    if not v:raise Invalid(code)

def pairs(items):
    value={}
    for k,v in items:
        require(k not in value,'JSON_DUPLICATE_KEY');value[k]=v
    return value

def int_limit(text):
    require(len(text.lstrip('-'))<=19,'JSON_INTEGER_LIMIT')
    return int(text)

def read_n(fd,offset,length):
    require(type(length) is int and length>=0,'READ_LENGTH')
    out=[];done=0
    while done<length:
        chunk=os.pread(fd,min(65536,length-done),offset+done)
        require(bool(chunk),'TRUNCATED')
        done+=len(chunk);out.append(chunk)
    return b''.join(out)

def lexical_preflight(raw):
    """Conservatively cap JSON structure before allocating a decoded tree.

    Tokens include each container, string (including object keys), and atom.
    This is not a JSON parser; json.loads still validates full syntax. Counting
    keys separately is intentionally stricter than the later value-node cap.
    """
    tokens=0;depth=0;in_string=False;escaped=False;raw_string=0;in_atom=False
    for ch in raw:
        if in_string:
            if escaped:
                escaped=False
            elif ch==0x5c:
                escaped=True
            elif ch==0x22:
                in_string=False
                continue
            raw_string+=1
            require(raw_string<=MAX_RAW_STRING,'JSON_STRING_RAW_LIMIT')
            continue
        if ch==0x22:
            tokens+=1;in_string=True;escaped=False;raw_string=0;in_atom=False
        elif ch in (0x5b,0x7b):
            tokens+=1;depth+=1;in_atom=False
            require(depth<=16,'JSON_COMPLEXITY')
        elif ch in (0x5d,0x7d):
            depth-=1;in_atom=False
            require(depth>=0,'JSON_STRUCTURE')
        elif ch in (0x20,0x09,0x0a,0x0d,0x2c,0x3a):
            in_atom=False
        elif not in_atom:
            tokens+=1;in_atom=True
        require(tokens<=MAX_NODES,'JSON_COMPLEXITY')
    require(not in_string and depth==0,'JSON_STRUCTURE')

def canonical_manifest(raw):
    require(0<len(raw)<=MAX_MANIFEST,'MANIFEST_LIMIT')
    lexical_preflight(raw)
    try:
        value=json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_int=int_limit,
                         parse_float=lambda _: (_ for _ in ()).throw(Invalid('JSON_FLOAT')),
                         parse_constant=lambda _: (_ for _ in ()).throw(Invalid('JSON_CONSTANT')))
    except (UnicodeError,ValueError,RecursionError) as exc:
        if isinstance(exc,Invalid): raise
        raise Invalid('MANIFEST_JSON') from exc
    # Iterator frames retain at most one active container per depth: unlike a
    # width-first stack.extend this does not allocate one tuple per list item.
    stack=[(iter((value,)),0)];nodes=0
    while stack:
        items,depth=stack[-1]
        try:item=next(items)
        except StopIteration:
            stack.pop();continue
        nodes+=1
        require(nodes<=MAX_NODES and depth<=16,'JSON_COMPLEXITY')
        if type(item) is dict:
            for k,v in item.items():
                require(type(k) is str and len(k)<=MAX_STR,'JSON_KEY')
            stack.append((iter(item.values()),depth+1))
        elif type(item) is list:stack.append((iter(item),depth+1))
        elif type(item) is str:require(len(item)<=MAX_STR,'JSON_STRING')
        elif item is None or type(item) is bool:pass
        elif type(item) is int:require(item.bit_length()<=63,'JSON_INTEGER_LIMIT')
        else:raise Invalid('JSON_TYPE')
    try: encoded=json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')
    except (TypeError,ValueError,UnicodeError,RecursionError) as exc:raise Invalid('JSON_ENCODING') from exc
    require(encoded==raw,'MANIFEST_NONCANONICAL')
    return value

def path_bytes(encoded):
    require(type(encoded) is str and len(encoded)<=4*((MAX_PATH+2)//3),'PATH_INVALID')
    try: value=base64.b64decode(encoded,validate=True)
    except (ValueError,UnicodeError) as exc:raise Invalid('PATH_INVALID') from exc
    require(base64.b64encode(value).decode('ascii')==encoded and 0<len(value)<=MAX_PATH,'PATH_INVALID')
    parts=value.split(b'/')
    require(len(parts)<=MAX_DEPTH and all(p not in (b'',b'.',b'..') and b'\0' not in p and p.lower()!=b'.git' for p in parts),'PATH_INVALID')
    return value

def no_prefix_collisions(paths):
    ordered=sorted(paths)
    for path in ordered:
        i=bisect.bisect_left(ordered,path+b'/')
        require(i==len(ordered) or not ordered[i].startswith(path+b'/'),'PATH_COLLISION')

def oid(kind,data,alg):
    return hashlib.new(alg,kind+b' '+str(len(data)).encode('ascii')+b'\0'+data).hexdigest()

def check_declaration(m,blobs,commit):
    keys={'schema','qualification','product_gate_effect','source_authentication','snapshot_atomicity','completeness_authority','head_commit_claim','git_object_format_claim','coverage_claims','head','index','tracked_worktree','untracked','excluded','staged_changes','unstaged_changes','unknown_worktree_modes','input_bytes_counting_each_projection'}
    require(type(m) is dict and set(m)==keys and m['schema']=='forgeflow.ecp-dirty-source-declaration.research.v1','DECLARATION_SCHEMA')
    require(m['qualification']=='NOT_RUN' and m['product_gate_effect']=='NONE' and m['source_authentication']=='UNVERIFIED' and m['snapshot_atomicity']=='UNKNOWN' and m['completeness_authority']=='UNVERIFIED','DECLARATION_AUTHORITY')
    alg=m['git_object_format_claim'];head=m['head_commit_claim']
    require(alg in ('sha1','sha256') and type(head) is str and re.fullmatch('[0-9a-f]{40}' if alg=='sha1' else '[0-9a-f]{64}',head) is not None,'HEAD_INVALID')
    require(oid(b'commit',commit,alg)==head,'COMMIT_OID_MISMATCH')
    header,sep,_body=commit.partition(b'\n\n');lines=header.split(b'\n')
    expected_header=b'tree '+(b'[0-9a-f]{40}' if alg=='sha1' else b'[0-9a-f]{64}')
    require(bool(sep) and b'\0' not in header and lines and re.fullmatch(expected_header,lines[0]) is not None and not any(x.startswith(b'tree ') for x in lines[1:]),'COMMIT_TREE_HEADER')
    claims=m['coverage_claims'];require(type(claims) is dict and set(claims)=={'head','index','worktree','exclusions'} and all(type(v) is bool for v in claims.values()),'COVERAGE_INVALID')
    rowkeys={'path_b64','kind','mode','byte_count','sha256','computed_git_blob_oid'}
    maps={};used=set();nrows=0;total=0;path_total=0
    for label in ('head','index','tracked_worktree','untracked'):
        rows=m[label];require(type(rows) is list and len(rows)<=MAX_ROWS,'ROWS_INVALID');entries={};prev=None
        for row in rows:
            require(type(row) is dict and set(row)==rowkeys,'ROW_INVALID')
            path=path_bytes(row['path_b64']);require(prev is None or prev<path,'ROW_ORDER');prev=path
            kind,mode,size,digest,git_oid=(row[k] for k in ('kind','mode','byte_count','sha256','computed_git_blob_oid'))
            require((kind,mode) in (('file','100644'),('file','100755'),('symlink','120000')) or (label in ('tracked_worktree','untracked') and kind=='file' and mode is None),'ROW_MODE')
            require(type(size) is int and 0<=size<=MAX_BLOB and type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None,'ROW_BLOB')
            raw=blobs.get(digest);require(type(raw) is bytes and len(raw)==size and hashlib.sha256(raw).hexdigest()==digest and oid(b'blob',raw,alg)==git_oid,'ROW_BLOB_MISMATCH')
            require(kind!='symlink' or (bool(raw) and b'\0' not in raw),'ROW_SYMLINK')
            nrows+=1;total+=size;path_total+=len(path)
            require(nrows<=MAX_ROWS and total<=MAX_TOTAL and path_total<=MAX_PATH_TOTAL,'ROW_BUDGET')
            entries[path]=(kind,mode,raw);used.add(digest)
        maps[label]=entries
    require(nrows>0,'ZERO_ROWS')
    require(set(blobs)==used,'BLOB_SET_MISMATCH')
    require(set(maps['tracked_worktree'])<=set(maps['index']) and not (set(maps['untracked'])&set(maps['index'])),'PROJECTION_RELATION')
    excluded=m['excluded'];require(type(excluded) is list and len(excluded)<=MAX_ROWS,'EXCLUSIONS_INVALID');excluded_map={};prev=None
    for row in excluded:
        require(type(row) is dict and set(row)=={'path_b64','reason'} and type(row['reason']) is str and 0<len(row['reason'])<=256,'EXCLUSION_ROW')
        path=path_bytes(row['path_b64']);require(prev is None or prev<path,'EXCLUSION_ORDER');prev=path
        excluded_map[path]=row['reason'];path_total+=len(path);require(path_total<=MAX_PATH_TOTAL,'PATH_BUDGET')
    for entries in (maps['head'],maps['index'],{**maps['tracked_worktree'],**maps['untracked']}):
        require(not(set(entries)&set(excluded_map)),'EXCLUSION_OVERLAP')
        no_prefix_collisions({**entries,**excluded_map})
    def changes(left,right,left_complete,right_complete):
        out=[]
        for p in sorted(set(left)|set(right)):
            a,b=left.get(p),right.get(p)
            if a==b:continue
            if a is None:c='ADDED' if left_complete else 'EXTRA_UNCONFIRMED'
            elif b is None:c='DELETED' if right_complete else 'MISSING_UNCONFIRMED'
            elif a[0]==b[0] and a[2]==b[2] and (a[1] is None or b[1] is None):c='INDETERMINATE_MODE'
            else:c='MODIFIED'
            out.append({'path_b64':base64.b64encode(p).decode('ascii'),'change':c})
        return out
    require(m['staged_changes']==changes(maps['head'],maps['index'],claims['head'],claims['index']) and m['unstaged_changes']==changes(maps['index'],maps['tracked_worktree'],claims['index'],claims['worktree']),'CHANGE_MISMATCH')
    combined={**maps['tracked_worktree'],**maps['untracked']}
    require(m['unknown_worktree_modes']==[base64.b64encode(p).decode('ascii') for p in sorted(combined) if combined[p][1] is None] and type(m['input_bytes_counting_each_projection']) is int and m['input_bytes_counting_each_projection']==total,'DERIVED_MISMATCH')
    # Independently reconstruct trees from the represented HEAD projection.
    trie={};nodes=0
    for path,(kind,mode,raw) in maps['head'].items():
        cur=trie;parts=path.split(b'/')
        for part in parts[:-1]:
            if part not in cur:cur[part]={};nodes+=1
            require(type(cur[part]) is dict,'TREE_COLLISION');cur=cur[part]
        require(parts[-1] not in cur,'TREE_COLLISION');cur[parts[-1]]=(mode,oid(b'blob',raw,alg));nodes+=1
        require(nodes<=20000,'TREE_BUDGET')
    def tree(node,depth):
        require(depth<=MAX_DEPTH,'TREE_DEPTH');rows=[]
        for name,value in node.items():
            if type(value) is dict: mode=b'40000';child=tree(value,depth+1);sortkey=name+b'/'
            else: mode=value[0].encode('ascii');child=value[1];sortkey=name+b'\0'
            rows.append((sortkey,mode+b' '+name+b'\0'+bytes.fromhex(child)))
        body=b''.join(x[1] for x in sorted(rows));return oid(b'tree',body,alg)
    require(tree(trie,0)==lines[0][5:].decode('ascii'),'COMMIT_TREE_MISMATCH')
    return m

def read(fd, expected_sha256):
    """Verify an already-owned sealed FD and return caller-scope observation."""
    require(type(expected_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_sha256) is not None,'BUNDLE_PIN_INVALID')
    require(all(hasattr(fcntl,x) for x in (*REQUIRED_NAMES,'F_GET_SEALS')),'SEAL_API_UNAVAILABLE')
    mask=0
    for name in REQUIRED_NAMES:mask|=getattr(fcntl,name)
    first=os.fstat(fd);require(stat.S_ISREG(first.st_mode) and 52<=first.st_size<=MAX_BUNDLE,'BUNDLE_SIZE')
    seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS);require(seals&mask==mask,'SEALS_MISSING')
    body=read_n(fd,0,first.st_size);require(hashlib.sha256(body).hexdigest()==expected_sha256,'BUNDLE_PIN_MISMATCH')
    require(hashlib.sha256(body[:-32]).digest()==body[-32:],'TRAILER_MISMATCH')
    magic,manifest_len,count,commit_len=struct.unpack_from('!8sIII',body,0)
    require(magic==MAGIC and 0<manifest_len<=MAX_MANIFEST and count<=MAX_BLOBS and 0<commit_len<=MAX_COMMIT,'HEADER_INVALID')
    end=len(body)-32;pos=20;require(pos+manifest_len+commit_len<=end,'TRUNCATED');raw_manifest=body[pos:pos+manifest_len];pos+=manifest_len
    blobs={};total=0;last=None
    for _ in range(count):
        require(pos+36<=end,'TRUNCATED');digest=body[pos:pos+32].hex();size=struct.unpack_from('!I',body,pos+32)[0];pos+=36
        require(size<=MAX_BLOB and pos+size<=end and (last is None or last<digest),'BLOB_ENCODING');last=digest
        raw=body[pos:pos+size];pos+=size;total+=size;require(total<=MAX_TOTAL and hashlib.sha256(raw).hexdigest()==digest,'BLOB_DIGEST')
        blobs[digest]=raw
    require(pos+commit_len==end,'BUNDLE_TRAILING_OR_TRUNCATED');commit=body[pos:end]
    manifest=check_declaration(canonical_manifest(raw_manifest),blobs,commit)
    laststat=os.fstat(fd);require((first.st_dev,first.st_ino,first.st_size)==(laststat.st_dev,laststat.st_ino,laststat.st_size) and fcntl.fcntl(fd,fcntl.F_GET_SEALS)&mask==mask,'FD_CHANGED')
    return {'status':'OBSERVED_RESEARCH_ONLY','qualification':'NOT_RUN','product_gate_effect':'NONE','bundle_sha256':expected_sha256,'manifest_sha256':hashlib.sha256(raw_manifest).hexdigest(),'head_commit_claim':manifest['head_commit_claim'],'blob_count':len(blobs),'blob_bytes':total,'seal_mask':seals,'source_authentication':'UNVERIFIED','snapshot_atomicity':'UNKNOWN','exclusion_authority':'UNVERIFIED','exclusion_coverage':'UNVERIFIED' if manifest['coverage_claims']['exclusions'] else 'UNKNOWN','projection_coverage':'CALLER_UNVERIFIED','directory_immutability':'NOT_MEASURED','principal_lease_db_binding':'UNVERIFIED','independent_actor':'NOT_MEASURED','durability':'NOT_MEASURED','manifest':manifest,'blobs':blobs,'commit':commit}
