import {useSyncExternalStore} from 'react';

export type UiTheme = 'glass' | 'studio' | 'classic';
export type ColorMode = 'light' | 'dark' | 'system';
interface Appearance {
  skin:UiTheme;
  mode:ColorMode;
  resolved:'light'|'dark';
  reduceTransparency:boolean;
  systemReduceTransparency:boolean;
  saved:boolean;
}
const keys={skin:'forgeflow.ui-theme',mode:'forgeflow.color-mode',legacy:'forgeflow.theme',transparency:'forgeflow.reduce-transparency'};
const systemDark=matchMedia('(prefers-color-scheme: dark)');
const systemTransparency=matchMedia('(prefers-reduced-transparency: reduce)');
const listeners=new Set<()=>void>();
const read=(key:string)=>{try{return localStorage.getItem(key);}catch{return null;}};
const validSkin=(value:unknown):value is UiTheme=>value==='glass'||value==='studio'||value==='classic';
const validMode=(value:unknown):value is ColorMode=>value==='light'||value==='dark'||value==='system';
function stored():Appearance {
  const skin=read(keys.skin),preferred=read(keys.mode),legacy=read(keys.legacy);
  const mode:ColorMode=validMode(preferred)?preferred:legacy==='dark'?'dark':legacy==='light'?'light':'system';
  return {skin:validSkin(skin)?skin:'glass',mode,resolved:mode==='system'?(systemDark.matches?'dark':'light'):mode,
    reduceTransparency:read(keys.transparency)==='true',systemReduceTransparency:systemTransparency.matches,saved:true};
}
let snapshot=stored();
let initialized=false;
function apply() {
  const root=document.documentElement;
  root.dataset.uiTheme=snapshot.skin;
  root.dataset.theme=snapshot.resolved;
  root.dataset.transparency=snapshot.reduceTransparency||snapshot.systemReduceTransparency?'reduced':'standard';
  document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute('content',snapshot.resolved==='dark'?'#121316':'#f4f5f7');
}
function publish(next:Appearance) {
  if(JSON.stringify(next)===JSON.stringify(snapshot))return;
  snapshot=next;apply();for(const notify of listeners)notify();
}
export function initializeAppearance() {
  if(initialized)return;initialized=true;apply();
  // Migrate once so a legacy resolved value cannot turn a new tab's system
  // preference into a fixed mode when another tab observes an OS change.
  if(!validMode(read(keys.mode))) {
    try{localStorage.setItem(keys.mode,snapshot.mode);}catch{publish({...snapshot,saved:false});}
  }
  systemDark.addEventListener('change',()=>{
    if(snapshot.mode!=='system')return;
    const resolved=systemDark.matches?'dark':'light';
    publish({...snapshot,resolved});
    try{localStorage.setItem(keys.legacy,resolved);}catch{/* The current appearance still applies. */}
  });
  systemTransparency.addEventListener('change',()=>publish({...snapshot,systemReduceTransparency:systemTransparency.matches}));
  window.addEventListener('storage',event=>{
    if(event.key===null||Object.values(keys).includes(event.key))publish(stored());
  });
}
export function setAppearance(change:Partial<Pick<Appearance,'skin'|'mode'|'reduceTransparency'>>) {
  const skin=validSkin(change.skin)?change.skin:snapshot.skin;
  const mode=validMode(change.mode)?change.mode:snapshot.mode;
  const reduceTransparency=typeof change.reduceTransparency==='boolean'?change.reduceTransparency:snapshot.reduceTransparency;
  const resolved=mode==='system'?(systemDark.matches?'dark':'light'):mode;
  let saved=true;
  try {
    localStorage.setItem(keys.skin,skin);localStorage.setItem(keys.mode,mode);
    localStorage.setItem(keys.legacy,resolved);localStorage.setItem(keys.transparency,String(reduceTransparency));
  } catch {saved=false;}
  publish({skin,mode,resolved,reduceTransparency,systemReduceTransparency:systemTransparency.matches,saved});
}
export function toggleColorMode(){setAppearance({mode:snapshot.resolved==='dark'?'light':'dark'});}
const subscribe=(notify:()=>void)=>{listeners.add(notify);return()=>{listeners.delete(notify);};};
export function useAppearance(){return useSyncExternalStore(subscribe,()=>snapshot,()=>snapshot);}
