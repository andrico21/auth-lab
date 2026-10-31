// Real desktop browser zoom only. No CDP scale, CSS transform or pinch substitution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawn, spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {DEFAULT_BROWSER, DEFAULT_PLAYWRIGHT, DEFAULT_LIBRARIES, fileIdentity, settle} from './compact-mobile-browser.mjs';

export const X11_ROOT = '/home/andrico/.cache/auth-lab-held-qa/next-desktop-tools-hsQCXd/runtime/usr/bin';
export function nativeIsolation() {
  const mount = fs.readFileSync('/proc/self/mountinfo','utf8').split('\n').find(line => line.split(' ')[4] === '/tmp');
  const networkNamespace = fs.readlinkSync('/proc/self/ns/net');
  const parentNetworkNamespace = process.env.COMPACT_NATIVE_PARENT_NETNS;
  return {mount,networkNamespace,parentNetworkNamespace,verified:!!mount && mount.includes(' - tmpfs ') && !!parentNetworkNamespace && networkNamespace !== parentNetworkNamespace};
}
export async function launchNativeZoom({out, modulePath = DEFAULT_PLAYWRIGHT,
  executablePath = DEFAULT_BROWSER, libraryPath = DEFAULT_LIBRARIES, toolRoot = X11_ROOT}) {
  const isolation=nativeIsolation();
  assert.equal(isolation.verified, true, 'Native X11 requires measured private tmpfs/tmp and separate network namespace; an acknowledgment flag is not isolation');
  const tools = Object.fromEntries(['Xvfb','xdotool','scrot'].map(name => [name,path.join(toolRoot,name)]));
  const imageLoaderPath=(process.env.IMLIB2_LOADER_PATH?[process.env.IMLIB2_LOADER_PATH]:libraryPath.split(path.delimiter).filter(Boolean).map(directory=>path.join(directory,'imlib2/loaders'))).find(directory=>fs.existsSync(path.join(directory,'png.so')));
  assert.ok(imageLoaderPath,'Provisioned scrot PNG loader required in IMLIB2_LOADER_PATH or an LD_LIBRARY_PATH/imlib2/loaders directory');
  const pngLoader=path.join(imageLoaderPath,'png.so');
  const identity = {tools:Object.fromEntries(Object.entries(tools).map(([name,file])=>[name,{path:file,...fileIdentity(file)}])),
    isolation,executable:{path:executablePath,...fileIdentity(executablePath)},module:{path:modulePath,...fileIdentity(modulePath)},libraryPath,imageLoader:{directory:imageLoaderPath,path:pngLoader,...fileIdentity(pngLoader)},
    mechanism:'Owned Xvfb -displayfd, native focused X11 Ctrl+0 and Ctrl+plus, DPR4 and visualViewport.scale1; no emulated browser zoom'};
  const stdout = fs.openSync(path.join(out,'xvfb.stdout'),'wx'), stderr = fs.openSync(path.join(out,'xvfb.stderr'),'wx');
  const xvfb = spawn(tools.Xvfb,['-displayfd','3','-screen','0','1360x1100x24','-nolisten','tcp','-ac'],
    {stdio:['ignore',stdout,stderr,'pipe'],env:{...process.env,LD_LIBRARY_PATH:libraryPath}});
  fs.closeSync(stdout); fs.closeSync(stderr);
  let browser, closed = false;
  async function close() {
    if (closed) return; closed = true;
    try { await browser?.close(); } finally {
      if (xvfb.exitCode === null) {
        xvfb.kill('SIGTERM');
        await new Promise(resolve=>{const timer=setTimeout(()=>{xvfb.kill('SIGKILL');resolve();},5000);xvfb.once('exit',()=>{clearTimeout(timer);resolve();});});
      }
    }
  }
  try {
    const display = await new Promise((resolve,reject)=>{
      let text=''; const timer=setTimeout(()=>reject(Error('Owned Xvfb displayfd startup timed out')),15000);
      xvfb.once('error',error=>{clearTimeout(timer);reject(error);});
      xvfb.once('exit',code=>{clearTimeout(timer);reject(Error('Owned Xvfb exited: '+code));});
      xvfb.stdio[3].on('data',bytes=>{text+=bytes;if(text.includes('\n')){clearTimeout(timer);assert.match(text.trim(),/^\d+$/);resolve(':'+text.trim());}});
    });
    const env={...process.env,DISPLAY:display,LD_LIBRARY_PATH:libraryPath,IMLIB2_LOADER_PATH:imageLoaderPath};
    const command=(name,args)=>{
      const result=spawnSync(tools[name],args,{env,encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
      assert.ifError(result.error);assert.equal(result.status,0,name+' '+args.join(' ')+' '+result.stderr);return result.stdout.trim();
    };
    const {chromium}=await import(pathToFileURL(modulePath).href);
    browser=await chromium.launch({executablePath,headless:false,env,args:['--window-size=1360,1100','--window-position=0,0','--force-device-scale-factor=1']});
    identity.version=browser.version(); identity.display=display;
    return {browser,identity,close,
      async apply(page,label) {
        const title='CompactNativeZoom-'+process.pid+'-'+label;
        await page.evaluate(title=>{document.title=title;},title);await page.bringToFront();await settle(page);
        const windows=command('xdotool',['search','--sync','--onlyvisible','--name','^'+title]).split('\n');
        assert.equal(windows.length,1,'Exactly one owned native browser window');const windowId=windows[0];
        const nativeTitle=command('xdotool',['getwindowname',windowId]);assert.ok(nativeTitle.startsWith(title));
        command('xdotool',['windowfocus','--sync',windowId]);
        command('xdotool',['key','--clearmodifiers','Escape']);command('xdotool',['key','--clearmodifiers','ctrl+0']);
        await page.waitForFunction(()=>Math.abs(devicePixelRatio-1)<.025 && visualViewport.scale===1);
        const observations=[];
        for(let step=0;step<8;step++) {
          command('xdotool',['key','--clearmodifiers','ctrl+plus']);await settle(page);
          observations.push(await page.evaluate(()=>({dpr:devicePixelRatio,scale:visualViewport.scale,width:innerWidth,height:innerHeight,focused:document.hasFocus()})));
        }
        await page.waitForFunction(()=>Math.abs(devicePixelRatio-4)<.025 && visualViewport.scale===1);
        const final=await page.evaluate(()=>({dpr:devicePixelRatio,scale:visualViewport.scale,width:innerWidth,height:innerHeight,focused:document.hasFocus()}));
        assert.equal(final.focused,true);assert.ok(final.width>=320&&final.width<=360,'Actual native400 browser reflow must be320..360CSSpx');
        return {windowId,nativeTitle,observations,final,mechanism:identity.mechanism};
      },
      async screenshot(page,file) {await page.bringToFront();command('scrot',[file]);}
    };
  } catch(error) {await close();throw error;}
}
