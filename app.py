#!/usr/bin/env python3
"""Company Wiki: Python standard library + SQLite, public reading / admin editing."""
import os, re, json, sqlite3, secrets, hashlib, hmac, html, time, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from http.cookies import SimpleCookie
from pathlib import Path
from datetime import datetime, timezone

BASE=Path(__file__).resolve().parent
DB=Path(os.environ.get('WIKI_DB_PATH',str(BASE/'wiki.sqlite3')))
HOST=os.environ.get('WIKI_HOST','127.0.0.1')
PORT=int(os.environ.get('WIKI_PORT','8080'))
SECURE=os.environ.get('WIKI_SECURE_COOKIE','0')=='1'
TITLE=os.environ.get('WIKI_TITLE','회사 업무 위키')
LOCK=threading.Lock()
LOGIN_ATTEMPTS={}

def conn():
 c=sqlite3.connect(DB,timeout=15);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=15000');return c

def password_hash(p,salt=None):
 salt=salt or secrets.token_bytes(16)
 return salt.hex()+':'+hashlib.scrypt(p.encode(),salt=salt,n=2**14,r=8,p=1).hex()

def verify(p,encoded):
 try:
  salt, digest=encoded.split(':');return hmac.compare_digest(password_hash(p,bytes.fromhex(salt)),encoded)
 except (ValueError,TypeError):return False

def init():
 DB.parent.mkdir(parents=True,exist_ok=True)
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, passhash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(tokenhash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id), csrf TEXT NOT NULL, expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, position INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY, category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','published')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS revisions(id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, saved_at TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_doc_status ON documents(status,updated_at);
 CREATE INDEX IF NOT EXISTS idx_doc_cat ON documents(category_id);''')
  if not c.execute('SELECT 1 FROM categories').fetchone():
   c.executemany('INSERT INTO categories(name,position) VALUES (?,?)',[(x,i) for i,x in enumerate(['회사 공통 업무','현장 업무','기술 매뉴얼','안전 관리','보고서 작성','자료실'])])
  if not c.execute('SELECT 1 FROM admins').fetchone():
   pwd=os.environ.get('WIKI_ADMIN_PASSWORD','')
   if len(pwd)<12:raise SystemExit('최초 실행 전 WIKI_ADMIN_PASSWORD 환경변수에 12자 이상의 비밀번호를 설정하세요.')
   username=os.environ.get('WIKI_ADMIN_USER','admin')
   c.execute('INSERT INTO admins(username,passhash) VALUES (?,?)',(username,password_hash(pwd)))

def e(s):return html.escape(str(s or ''),quote=True)
def now():return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
def shorten(s,n=130):return s[:n]+('…' if len(s)>n else '')
def layout(content,admin=False,csrf='',search='',title=''):
 with conn() as c: cats=c.execute('SELECT * FROM categories ORDER BY position,name').fetchall()
 menu=''.join(f'<a href="/?cat={r["id"]}">▸ {e(r["name"])}</a>' for r in cats)
 action='<a class="admin" href="/admin">관리 화면</a>' if admin else '<a class="admin" href="/login">관리자 로그인</a>'
 return f'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title or TITLE)}</title><style>
 :root{{--navy:#16263c;--accent:#2366cc;--bg:#f5f7fb;--line:#e2e7f0}}*{{box-sizing:border-box}}body{{margin:0;font-family:system-ui,-apple-system,'Malgun Gothic',sans-serif;color:#263346;background:var(--bg)}}a{{color:inherit;text-decoration:none}}header{{height:64px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 28px;gap:10px}}header strong{{font-size:18px;color:var(--navy)}}header a{{font-size:13px;color:#37619c}}.shell{{display:flex;min-height:calc(100vh - 64px)}}aside{{width:235px;background:#fff;border-right:1px solid var(--line);padding:25px 15px;flex-shrink:0}}aside a{{display:block;padding:11px 12px;border-radius:8px;font-size:14px}}aside a:hover,.tile:hover{{background:#edf3fc}}aside small{{display:block;color:#8793a6;font-weight:700;margin:0 12px 12px}}main{{max-width:1100px;width:100%;padding:35px;margin:auto;align-self:flex-start}}h1{{font-size:27px;margin:0 0 12px}}h2{{font-size:19px}}p{{line-height:1.8}}.muted{{color:#7d899a;font-size:13px}}.panel{{background:white;border:1px solid var(--line);border-radius:13px;padding:25px;margin:20px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}.tile{{background:white;border:1px solid var(--line);border-radius:12px;padding:19px;display:block}}.tile b{{display:block;margin-bottom:8px}}input,textarea,select{{width:100%;padding:12px;border:1px solid #ccd6e4;border-radius:8px;font:inherit;margin:7px 0 17px;background:#fff}}textarea{{min-height:320px;resize:vertical;line-height:1.6}}label{{font-weight:600;font-size:14px}}button,.btn{{display:inline-block;border:0;border-radius:8px;background:var(--accent);color:#fff;padding:11px 18px;cursor:pointer;font:inherit;margin:3px 5px 3px 0}}.secondary{{background:#e9eef6;color:#263346}}.danger{{background:#b33636}}.doc{{padding:15px 0;border-bottom:1px solid var(--line)}}.doc a{{font-weight:600;color:#205baf}}.body{{white-space:pre-wrap;line-height:1.9;overflow-wrap:anywhere}}.toolbar{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}.pill{{background:#e9f1ff;color:#1d5bb6;padding:4px 9px;border-radius:12px;font-size:12px}}.error{{background:#ffebeb;padding:12px;border-radius:8px;color:#9b2323}}.admin{{white-space:nowrap}}@media(max-width:720px){{header{{padding:0 15px}}aside{{width:100%;border-right:0;border-bottom:1px solid var(--line);padding:10px;display:flex;flex-wrap:wrap;gap:3px}}aside small{{display:none}}aside a{{padding:8px;font-size:12px}}.shell{{display:block}}main{{padding:18px}}.panel{{padding:17px}}h1{{font-size:23px}}}}
 </style></head><body><header><a href="/"><strong>▣ {e(TITLE)}</strong></a>{action}</header><div class="shell"><aside><small>업무 지식 탐색</small><a href="/">⌂ 전체 문서</a>{menu}</aside><main>{content}</main></div></body></html>'''

class Handler(BaseHTTPRequestHandler):
 def log_message(self,fmt,*args): print('%s %s'%(self.address_string(),fmt%args))
 def send(self,body,status=200,headers=None):
  b=body.encode('utf-8');self.send_response(status);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(b)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");self.send_header('Cache-Control','no-store');
  for k,v in (headers or {}).items():self.send_header(k,v)
  self.end_headers();self.wfile.write(b)
 def redirect(self,to,headers=None):self.send('',303,{'Location':to,**(headers or {})})
 def session(self):
  try:
   ck=SimpleCookie();ck.load(self.headers.get('Cookie',''));token=ck['wiki_session'].value
   with conn() as c:return c.execute('SELECT * FROM sessions WHERE tokenhash=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
  except (KeyError,ValueError):return None
 def cookie(self,value,maxage=0):return f'wiki_session={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={maxage}'+('; Secure' if SECURE else '')
 def params(self):return parse_qs(urlparse(self.path).query)
 def form(self):
  n=int(self.headers.get('Content-Length','0'))
  if n>1024*1024:raise ValueError('요청 크기 초과')
  return {k:v[0] for k,v in parse_qs(self.rfile.read(n).decode('utf-8'),keep_blank_values=True).items()}
 def csrf_ok(self,s,f):return bool(s and hmac.compare_digest(s['csrf'],f.get('csrf','')))
 def bad(self,msg,status=400):self.send(layout(f'<div class="panel error">{e(msg)}</div>',bool(self.session())),status)
 def do_GET(self):
  path=urlparse(self.path).path;s=self.session();admin=bool(s);q=self.params()
  if path=='/':
   cat=q.get('cat',[''])[0];search=q.get('q',[''])[0].strip()[:100];where=["d.status='published'"];args=[]
   if cat.isdigit():where.append('d.category_id=?');args.append(int(cat))
   if search:where.append('(d.title LIKE ? OR d.body LIKE ?)');args.extend(['%'+search+'%']*2)
   with conn() as c: docs=c.execute('SELECT d.*,c.name cat FROM documents d LEFT JOIN categories c ON d.category_id=c.id WHERE '+' AND '.join(where)+' ORDER BY d.updated_at DESC LIMIT 200',args).fetchall()
   items=''.join(f'<div class="doc"><a href="/doc/{r["id"]}">{e(r["title"])}</a><p class="muted">{e(r["cat"] or "미분류")} · 수정 {e(r["updated_at"])}</p><div class="muted">{e(shorten(r["body"].replace(chr(10)," ")))}</div></div>' for r in docs) or '<p class="muted">등록된 공개 문서가 없습니다.</p>'
   body=f'<h1>회사 업무 매뉴얼</h1><p class="muted">업무 절차와 자료를 검색하고 확인하세요.</p><form action="/" method="get"><input name="q" value="{e(search)}" placeholder="매뉴얼 제목이나 내용 검색"><button>검색</button></form><div class="panel"><h2>공개 문서 <span class="pill">{len(docs)}개</span></h2>{items}</div>'
  elif path.startswith('/doc/') and path[5:].isdigit():
   with conn() as c:r=c.execute('SELECT d.*,c.name cat FROM documents d LEFT JOIN categories c ON d.category_id=c.id WHERE d.id=?',(int(path[5:]),)).fetchone()
   if not r or (r['status']!='published' and not admin):return self.bad('문서를 찾을 수 없습니다.',404)
   edit=f'<a class="btn" href="/admin/edit/{r["id"]}">문서 수정</a>' if admin else ''
   body=f'<a href="/">← 문서 목록</a><div class="panel"><span class="pill">{e(r["cat"] or "미분류")}</span> <span class="pill">{e(r["status"])}</span><h1 style="margin-top:15px">{e(r["title"])}</h1><p class="muted">최근 수정: {e(r["updated_at"])}</p><hr style="border:0;border-top:1px solid #eee"><div class="body">{e(r["body"])}</div></div>{edit}'
  elif path=='/login':
   if admin:return self.redirect('/admin')
   body='<h1>관리자 로그인</h1><div class="panel" style="max-width:460px"><form method="post" action="/login"><label>관리자 ID</label><input name="username" autocomplete="username" required><label>비밀번호</label><input type="password" name="password" autocomplete="current-password" required><button>로그인</button></form></div>'
  elif path=='/admin':
   if not admin:return self.redirect('/login')
   with conn() as c:docs=c.execute('SELECT d.*,c.name cat FROM documents d LEFT JOIN categories c ON c.id=d.category_id ORDER BY d.updated_at DESC').fetchall();cats=c.execute('SELECT * FROM categories ORDER BY position,name').fetchall()
   rows=''.join(f'<div class="doc"><a href="/admin/edit/{r["id"]}">{e(r["title"])}</a> <span class="pill">{e(r["status"])}</span><p class="muted">{e(r["cat"] or "미분류")} · {e(r["updated_at"])}</p></div>' for r in docs) or '<p class="muted">문서가 없습니다.</p>'
   catrows=''.join(f'<div class="toolbar"><span>{e(r["name"])}</span><form method="post" action="/admin/category/delete" onsubmit="return confirm(\'분류를 삭제할까요?\')"><input type="hidden" name="csrf" value="{e(s["csrf"])}"><input type="hidden" name="id" value="{r["id"]}"><button class="secondary">삭제</button></form></div>' for r in cats)
   body=f'<h1>관리자 대시보드</h1><div class="toolbar"><a class="btn" href="/admin/new">+ 새 문서</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="{e(s["csrf"])}"><button class="secondary">로그아웃</button></form></div><div class="panel"><h2>전체 문서 ({len(docs)})</h2>{rows}</div><div class="panel"><h2>카테고리 관리</h2>{catrows}<form method="post" action="/admin/category"><input type="hidden" name="csrf" value="{e(s["csrf"])}"><label>새 카테고리</label><input name="name" maxlength="70" required><button>추가</button></form></div>'
  elif path=='/admin/new' or (path.startswith('/admin/edit/') and path[12:].isdigit()):
   if not admin:return self.redirect('/login')
   docid=int(path[12:]) if path!='/admin/new' else None
   with conn() as c:
    r=c.execute('SELECT * FROM documents WHERE id=?',(docid,)).fetchone() if docid else None
    cats=c.execute('SELECT * FROM categories ORDER BY position,name').fetchall()
    revs=c.execute('SELECT id,saved_at,title FROM revisions WHERE document_id=? ORDER BY id DESC LIMIT 20',(docid,)).fetchall() if docid else []
   if docid and not r:return self.bad('문서를 찾을 수 없습니다.',404)
   opts=''.join(f'<option value="{x["id"]}" {"selected" if r and r["category_id"]==x["id"] else ""}>{e(x["name"])}</option>' for x in cats)
   status=r['status'] if r else 'draft';body=f'''<h1>{'문서 수정' if r else '새 문서'}</h1><div class="panel"><form method="post" action="/admin/save"><input type="hidden" name="csrf" value="{e(s['csrf'])}"><input type="hidden" name="id" value="{docid or ''}"><label>문서 제목</label><input name="title" maxlength="180" required value="{e(r['title'] if r else '')}"><label>카테고리</label><select name="category_id"><option value="">미분류</option>{opts}</select><label>문서 내용 (일반 텍스트)</label><textarea name="body" required>{e(r['body'] if r else '')}</textarea><label>공개 상태</label><select name="status"><option value="draft" {'selected' if status=='draft' else ''}>임시저장 — 관리자만 열람</option><option value="published" {'selected' if status=='published' else ''}>게시 — 누구나 열람</option></select><button>저장</button><a class="btn secondary" href="/admin">취소</a></form></div>'''
   if r:
    versions=''.join(f'<form method="post" action="/admin/restore"><input type="hidden" name="csrf" value="{e(s["csrf"])}"><input type="hidden" name="revision_id" value="{v["id"]}"><span>{e(v["saved_at"])} — {e(v["title"])}</span> <button class="secondary">이 버전 복원</button></form>' for v in revs) or '<p class="muted">수정 이력 없음</p>'
    body+=f'<div class="panel"><h2>이전 버전</h2>{versions}</div><form method="post" action="/admin/delete" onsubmit="return confirm(\'이 문서와 모든 수정 이력을 삭제할까요?\')"><input type="hidden" name="csrf" value="{e(s["csrf"])}"><input type="hidden" name="id" value="{docid}"><button class="danger">문서 영구 삭제</button></form>'
  else:return self.bad('페이지를 찾을 수 없습니다.',404)
  self.send(layout(body,admin,title=TITLE))
 def do_POST(self):
  path=urlparse(self.path).path
  try:f=self.form()
  except (ValueError,UnicodeError):return self.bad('잘못된 요청입니다.')
  if path=='/login':
   ip=self.client_address[0];t=time.time()
   with LOCK:
    attempts=[x for x in LOGIN_ATTEMPTS.get(ip,[]) if t-x<900]
    if len(attempts)>=10:return self.bad('로그인 시도가 너무 많습니다. 15분 후 다시 시도하세요.',429)
    attempts.append(t);LOGIN_ATTEMPTS[ip]=attempts
   with conn() as c:a=c.execute('SELECT * FROM admins WHERE username=?',(f.get('username',''),)).fetchone()
   if not a or not verify(f.get('password',''),a['passhash']):return self.bad('ID 또는 비밀번호가 올바르지 않습니다.',401)
   token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
   with conn() as c:
    c.execute('DELETE FROM sessions WHERE expires<?',(int(t),));c.execute('INSERT INTO sessions VALUES (?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),a['id'],csrf,int(t)+28800))
   with LOCK:LOGIN_ATTEMPTS.pop(ip,None)
   return self.redirect('/admin',{'Set-Cookie':self.cookie(token,28800)})
  s=self.session()
  if not self.csrf_ok(s,f):return self.bad('관리자 로그인 또는 보안 토큰이 필요합니다.',403)
  if path=='/logout':
   ck=SimpleCookie();ck.load(self.headers.get('Cookie',''))
   with conn() as c:c.execute('DELETE FROM sessions WHERE tokenhash=?',(hashlib.sha256(ck['wiki_session'].value.encode()).hexdigest(),))
   return self.redirect('/',{'Set-Cookie':self.cookie('',0)})
  if path=='/admin/category':
   name=f.get('name','').strip()[:70]
   if not name:return self.bad('카테고리 이름을 입력하세요.')
   try:
    with conn() as c:c.execute('INSERT INTO categories(name,position) VALUES (?,(SELECT COALESCE(MAX(position),0)+1 FROM categories))',(name,))
   except sqlite3.IntegrityError:return self.bad('이미 존재하는 카테고리입니다.')
  elif path=='/admin/category/delete':
   with conn() as c:c.execute('DELETE FROM categories WHERE id=?',(f.get('id',''),))
  elif path=='/admin/save':
   title=f.get('title','').strip()[:180];body=f.get('body','').strip();status=f.get('status','draft');cat=f.get('category_id','')
   if not title or not body or len(body)>200000 or status not in ('draft','published'):return self.bad('문서 내용을 확인하세요 (최대 20만 자).')
   cat=int(cat) if cat.isdigit() else None
   with conn() as c:
    if f.get('id','').isdigit():
     docid=int(f['id']);old=c.execute('SELECT * FROM documents WHERE id=?',(docid,)).fetchone()
     if not old:return self.bad('문서를 찾을 수 없습니다.',404)
     c.execute('INSERT INTO revisions(document_id,title,body,status,saved_at) VALUES (?,?,?,?,?)',(docid,old['title'],old['body'],old['status'],now()))
     c.execute('UPDATE documents SET title=?,body=?,category_id=?,status=?,updated_at=? WHERE id=?',(title,body,cat,status,now(),docid))
    else:c.execute('INSERT INTO documents(title,body,category_id,status,created_at,updated_at) VALUES (?,?,?,?,?,?)',(title,body,cat,status,now(),now()))
  elif path=='/admin/restore':
   with conn() as c:
    rev=c.execute('SELECT * FROM revisions WHERE id=?',(f.get('revision_id',''),)).fetchone()
    if not rev:return self.bad('버전을 찾을 수 없습니다.',404)
    old=c.execute('SELECT * FROM documents WHERE id=?',(rev['document_id'],)).fetchone()
    if not old:return self.bad('문서를 찾을 수 없습니다.',404)
    c.execute('INSERT INTO revisions(document_id,title,body,status,saved_at) VALUES (?,?,?,?,?)',(old['id'],old['title'],old['body'],old['status'],now()))
    c.execute('UPDATE documents SET title=?,body=?,status=?,updated_at=? WHERE id=?',(rev['title'],rev['body'],rev['status'],now(),old['id']))
   return self.redirect('/admin/edit/'+str(rev['document_id']))
  elif path=='/admin/delete':
   with conn() as c:c.execute('DELETE FROM documents WHERE id=?',(f.get('id',''),))
  else:return self.bad('요청을 찾을 수 없습니다.',404)
  self.redirect('/admin')

if __name__=='__main__':
 init();print(f'Wiki running at http://{HOST}:{PORT}');ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
