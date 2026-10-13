// Garde l'interface et les images en cache ; les données viennent toujours du réseau.
// Reçoit aussi les notifications du groupe, même appli fermée.
const CACHE="japon-2027-v34";
const SHELL=["./","index.html","vendor-supabase.js"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE&&k!=="japon-meta").map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=="GET"||u.origin!==location.origin)return;
  if(/\/(img|icons)\//.test(u.pathname)){
    e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).then(res=>{const c=res.clone();caches.open(CACHE).then(ca=>ca.put(e.request,c));return res})));
    return;
  }
  // Toujours demander la version la plus récente au serveur (sans passer par la mémoire du navigateur).
  const fresh=e.request.mode==="navigate"?fetch(e.request.url,{cache:"no-cache",credentials:"same-origin"}):fetch(e.request,{cache:"no-cache"});
  e.respondWith(fresh.then(res=>{const c=res.clone();caches.open(CACHE).then(ca=>ca.put(e.request,c));return res}).catch(()=>caches.match(e.request,{ignoreSearch:true}).then(r=>r||caches.match("index.html"))));
});
self.addEventListener("push",e=>{
  let d={};try{d=e.data?e.data.json():{}}catch(_){d={body:e.data?e.data.text():""}}
  const icon="icons/"+(d.icon||"torii")+"-192.png";
  e.waitUntil((async()=>{
    let n=1;
    try{const ca=await caches.open("japon-meta");const r=await ca.match("badge");n=(r?Number(await r.text())||0:0)+1;await ca.put("badge",new Response(String(n)))}catch(_){}
    try{if(self.navigator&&self.navigator.setAppBadge)await self.navigator.setAppBadge(n)}catch(_){}
    await self.registration.showNotification(d.title||"Japon 2027",{body:d.body||"Nouveauté dans le voyage",icon,badge:"icons/torii-96.png",data:{tab:d.tab||"prep"}});
  })());
});
self.addEventListener("notificationclick",e=>{
  e.notification.close();
  const t=(e.notification.data&&e.notification.data.tab)||"prep";
  const url=new URL("./?tab="+t,self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({type:"window",includeUncontrolled:true}).then(cs=>{
    for(const c of cs){if("focus" in c){c.postMessage({type:"openTab",tab:t});return c.focus()}}
    return self.clients.openWindow(url);
  }));
});
