/* global chrome */
// A real HTTPS document is still required. This controls only how it is opened.
var BridgeSigningPage = (() => {
  async function close(page){
    if(Number.isInteger(page?.windowId))await chrome.windows.remove(page.windowId).catch(()=>{});
    else if(Number.isInteger(page?.tabId))await chrome.tabs.remove(page.tabId).catch(()=>{});
  }
  async function popupBounds(){
    const bounds={width:240,height:160};
    try{
      const anchor=await chrome.windows.getLastFocused({windowTypes:['normal']});
      if([anchor.left,anchor.top,anchor.width,anchor.height].every(Number.isFinite)&&
         anchor.width>=200&&anchor.height>=200){
        bounds.width=Math.min(bounds.width,anchor.width-16);
        bounds.height=Math.min(bounds.height,anchor.height-16);
        bounds.left=Math.round(anchor.left+anchor.width-bounds.width-8);
        bounds.top=Math.round(anchor.top+anchor.height-bounds.height-8);
      }
    }catch{} // Let Chrome place it if there is no normal browser window.
    return bounds;
  }
  async function open(url,background=false){
    if(!background){
      const tab=await chrome.tabs.create({url,active:true});
      return {tabId:tab.id,windowId:null};
    }
    let windowId=null;
    try{
      // Chrome rejects fully off-screen bounds. Request a small unfocused
      // popup inside the last normal browser window instead.
      const bounds=await popupBounds();
      const win=await chrome.windows.create({url,type:'popup',focused:false,...bounds});
      windowId=win.id;
      if(!Number.isInteger(windowId))throw Error('Signing window did not return an ID');
      const tabs=win.tabs?.length?win.tabs:await chrome.tabs.query({windowId});
      if(!Number.isInteger(tabs[0]?.id))throw Error('Signing window did not return a tab');
      return {tabId:tabs[0].id,windowId};
    }catch(e){
      if(Number.isInteger(windowId))await close({windowId});
      throw e;
    }
  }
  return {open,close};
})();
