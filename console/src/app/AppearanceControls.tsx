import {useId,useState} from 'react';
import {createPortal} from 'react-dom';
import {Check,Monitor,Moon,Palette,Sun,Layers3,SlidersHorizontal} from 'lucide-react';
import {Drawer} from '../components';
import {setAppearance,useAppearance,type UiTheme,type ColorMode} from './appearance';

const themes=[
  {id:'glass' as const,title:'Glass',subtitle:'轻盈通透',description:'柔和磨砂、圆润控件与清晰留白，让日常规划更从容。'},
  {id:'studio' as const,title:'Studio',subtitle:'专业石墨',description:'精细边框、石墨层次与紧凑秩序，专注复杂项目。'},
];
export function ThemeMiniature({skin}:{skin:Exclude<UiTheme,'classic'>}) {
  return <span className={`theme-miniature theme-miniature-${skin}`} aria-hidden="true">
    <span className="mini-window"><span className="mini-toolbar"><i/><i/><i/><b/></span>
      <span className="mini-sidebar"><em/><i/><i/><i/><span/></span>
      <span className="mini-content"><span className="mini-title"/><span className="mini-caption"/><span className="mini-metrics"><i/><i/><i/></span><span className="mini-table"><i/><i/><i/></span></span>
    </span>
  </span>;
}
export function AppearanceControls() {
  const state=useAppearance(),id=useId();
  const selected=themes.find(theme=>theme.id===state.skin);
  const modes:{id:ColorMode;label:string;icon:typeof Sun}[]=[{id:'light',label:'浅色',icon:Sun},{id:'dark',label:'深色',icon:Moon},{id:'system',label:'跟随系统',icon:Monitor}];
  return <div className="appearance-controls">
    <div className="appearance-intro"><span className="appearance-mark"><Layers3 size={22} strokeWidth={1.5}/></span><div><h3>一个工作空间，两种专注方式。</h3><p>选择适合你的界面，切换即刻生效。</p></div></div>
    <fieldset className="appearance-fieldset"><legend>界面主题</legend><div className="appearance-theme-options">
      {themes.map(theme=><label key={theme.id} className={`appearance-theme-card ${state.skin===theme.id?'is-selected':''}`}>
        <input type="radio" name={`${id}-theme`} value={theme.id} checked={state.skin===theme.id} aria-label={`${theme.title} ${theme.subtitle}`} onChange={()=>setAppearance({skin:theme.id})}/>
        <ThemeMiniature skin={theme.id}/><span className="appearance-theme-heading"><strong>{theme.title}</strong><span className="appearance-check">{state.skin===theme.id?<Check size={13}/>:null}</span></span>
        <span className="appearance-theme-subtitle">{theme.subtitle}</span><span className="appearance-theme-description">{theme.description}</span>
      </label>)}
    </div></fieldset>
    <fieldset className="appearance-fieldset"><legend>明暗外观</legend><div className="appearance-mode-picker">
      {modes.map(mode=><label key={mode.id} className={state.mode===mode.id?'is-selected':''}><input type="radio" name={`${id}-mode`} value={mode.id} checked={state.mode===mode.id} aria-label={mode.label} onChange={()=>setAppearance({mode:mode.id})}/><mode.icon size={15}/><span>{mode.label}</span></label>)}
    </div></fieldset>
    <label className="appearance-transparency"><span className="appearance-preference-icon"><SlidersHorizontal size={17}/></span><span><strong>减少透明效果</strong><small id={`${id}-transparency-help`}>{state.systemReduceTransparency?'系统已启用减少透明效果':'使用更实的导航与面板背景'}</small></span><input type="checkbox" aria-label="减少透明效果" aria-describedby={`${id}-transparency-help`} checked={state.reduceTransparency||state.systemReduceTransparency} disabled={state.systemReduceTransparency} onChange={event=>setAppearance({reduceTransparency:event.target.checked})}/></label>
    <div className="appearance-footer"><span role="status">{state.saved?`${selected?.title||'原有样式'} · ${state.mode==='system'?'跟随系统':state.resolved==='dark'?'深色':'浅色'} · 已保存在此浏览器`:'已应用，浏览器暂时无法保存偏好'}</span><button type="button" className="quiet-button" aria-pressed={state.skin==='classic'} onClick={()=>setAppearance({skin:'classic'})}>使用原有样式</button></div>
  </div>;
}
export function AppearanceButton({welcome=false}:{welcome?:boolean}) {
  const [open,setOpen]=useState(false);
  return <>
    <button type="button" className={`appearance-trigger ${welcome?'welcome-theme':'icon-button'}`} aria-label="外观与主题" title="外观与主题" onClick={()=>setOpen(true)}><Palette size={welcome?18:17}/>{welcome&&<span>外观</span>}</button>
    {open&&createPortal(<div data-appearance-dialog="true"><Drawer title="外观与主题" onClose={()=>setOpen(false)} animateClose><AppearanceControls/></Drawer></div>,document.body)}
  </>;
}
