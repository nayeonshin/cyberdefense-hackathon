export default function render({parentElement, data}) {
  const root = parentElement.querySelector('.motion-app');
  if (root._defenseMotion) {
    root._defenseMotion.update(data);
    return root._defenseMotion.dispose;
  }
  const canvas = root.querySelector('canvas'), ctx = canvas.getContext('2d');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const memory = root._motionMemory || {};
  let model = data, lastDelivery = performance.now(), signature = '', replay = false;
  let paused = memory.paused || false, visualTime = memory.visualTime || 0, stage = 0, elapsed = 0;
  let raf = 0, last = 0, lastPaint = 0, w = 0, h = 0, dpr = 1, visible = true, disposed = false;
  let colors = {}, priorReceipt = null, priorEvent = null, renderedPhase = '';
  const appearance = {energy:75, trails:true};
  const steps = [...root.querySelectorAll('.stages li')];
  const pauseButton = root.querySelector('.pause'), replayButton = root.querySelector('.replay');
  try { paused = sessionStorage.getItem('defense-motion-paused') === 'true'; } catch (_) { /* Storage is optional. */ }
  root.dataset.instance = String(Date.now());
  const healthy = () => !model.degraded && performance.now() - lastDelivery < 8000;
  const stopped = () => paused || reduced.matches || !visible || document.hidden || !healthy() || !ctx;
  function text(selector, value) {
    const el = root.querySelector(selector), next = String(value ?? '');
    if (el.textContent !== next) el.textContent = next;
  }
  function remember() {
    root._motionMemory = {paused, visualTime};
    try {sessionStorage.setItem('defense-motion-paused', String(paused));} catch (_) { /* Keep in-memory state. */ }
  }
  function colorTokens() {
    colors = {a:getComputedStyle(root.querySelector('.color-primary')).color,
      b:getComputedStyle(root.querySelector('.color-secondary')).color,
      hot:getComputedStyle(root.querySelector('.color-hot')).color};
  }
  function resize() {
    const bounds = canvas.getBoundingClientRect(); w = bounds.width; h = bounds.height;
    if (ctx) {dpr = Math.min(devicePixelRatio || 1, 1.5); canvas.width = Math.round(w*dpr);
      canvas.height = Math.round(h*dpr); ctx.setTransform(dpr,0,0,dpr,0,0); colorTokens(); draw();}
  }
  function replayStage() {
    const dates = model.stages.map(s => Date.parse(s.recorded));
    const duration = dates[3] - dates[0];
    const point = dates[0] + duration * Math.min(1, elapsed / 15);
    return dates.reduce((current, time, i) => time <= point ? i : current, 0);
  }
  function paintText() {
    const good = healthy();
    if (!good || reduced.matches) replay = false;
    stage = replay ? replayStage() : model.latest;
    root.dataset.displayStage = String(stage); root.dataset.replay = String(replay);
    root.classList.toggle('is-replaying', replay); root.classList.toggle('is-stopped', stopped());
    root.classList.toggle('is-degraded', !good);
    text('.pause', paused ? 'Resume motion' : 'Pause motion');
    pauseButton.disabled = reduced.matches || !good || !ctx;
    replayButton.disabled = !model.replay || !good || reduced.matches || !ctx;
    text('.replay', replay ? 'Return to current evidence' : 'Replay saved evidence');
    text('.watchdog', performance.now()-lastDelivery >= 8000 ? 'Live updates unavailable · Saved evidence shown' :
      model.degraded ? 'Pipeline degraded · Saved evidence shown' : replay ? 'Saved evidence replay · No actions dispatched' : '');
    text('.motion-mode', !ctx ? 'Static view' : reduced.matches ? 'Reduced motion' : !good ? 'Motion stopped' : paused ? 'Motion paused' : 'Motion on');
    text('.motion-note', replay ? 'Saved evidence replay · Read-only' : 'Ambient motion · Recorded progress below');
    text('.source-note', model.simulated ? 'Simulated data · No live scans or reports' : 'Read-only view · Progress comes from event metadata and receipts');
    text('.duration', model.duration != null ? model.duration.toFixed(3) + 's recorded' : 'Time not recorded');
    text('.event-id', model.event_id ? 'EVENT / ' + model.event_id : 'EVENT / WAITING');
    text('.target', model.target);
    const labels = ['Recorded discovery', 'Recorded scan', 'Saved report', 'Recorded confirmation'];
    const status = replay ? labels[stage] : model.status;
    text('.field-status', !good ? 'Data degraded · Saved evidence' : (model.simulated ? 'Simulated · ' : '') + status);
    text('.status', status); root.querySelector('.status').dataset.tone = model.tone;
    const headlines = ['A signal enters the pipeline.', 'The evidence stays in view.', 'An action has a receipt.', 'The outcome is recorded.'];
    text('.headline', model.phase === 'empty' ? 'Waiting for the next signal.' : headlines[stage]);
    text('.core-label', model.simulated ? 'SIMULATED DATA' : replay ? 'SAVED EVIDENCE REPLAY' : 'RECORDED EVIDENCE');
    text('.core-value', stage === 1 ? model.confidence : stage === 2 ? 'SENT' : stage === 3 ?
      (model.phase === 'historical' ? 'HISTORICAL' : 'CONFIRMED') : model.event_id ? '01' : '—');
    let evidence = model.evidence, scanner = model.scanner, confidence = 'Confidence ' + model.confidence;
    if (replay && stage === 0) {evidence = 'Target: ' + model.target + '\nIngested: ' + model.stages[0].time;
      scanner = 'Recorded ingestion'; confidence = '';}
    if (replay && stage === 2) {evidence = model.receipt.detail; scanner = 'Saved Actor receipt'; confidence = 'SENT';}
    if (replay && stage === 3) {evidence = model.stages[3].detail + '\nRecorded: ' + model.stages[3].time;
      scanner = 'Saved confirmation'; confidence = '';}
    text('.evidence', evidence); text('.scanner', scanner); text('.confidence', confidence);
    const showReceipt = !!model.receipt && (!replay || stage >= 2);
    const receipt = root.querySelector('.receipt'); receipt.hidden = !showReceipt;
    root.querySelector('.no-receipt').hidden = showReceipt;
    if (showReceipt) {
      text('.receipt-action', model.receipt.action); text('.receipt-detail', model.receipt.detail);
      text('.receipt-time', model.receipt.created_at);
    }
    const phaseKey = model.event_id + ':' + replay + ':' + stage;
    if (phaseKey !== renderedPhase) {
      receipt.classList.remove('is-new');
      if (replay && stage === 2 && !reduced.matches) {void receipt.offsetWidth; receipt.classList.add('is-new');}
      renderedPhase = phaseKey;
    }
    root.querySelector('.evidence-link').hidden = !model.event_id;
    steps.forEach((el,i) => {
      const s = model.stages[i];
      el.classList.toggle('is-current', !!s && i === stage);
      el.classList.toggle('is-reached', !!s?.reached);
      el.classList.toggle('is-historical', !!s?.historical);
      const detail = el.querySelector('.step-detail'), stamp = el.querySelector('.step-time');
      if (detail.textContent !== (s?.detail || 'Not recorded')) detail.textContent = s?.detail || 'Not recorded';
      if (stamp.textContent !== (s?.time || '')) stamp.textContent = s?.time || '';
      el.querySelector('.track>span').style.width = s?.reached && (!replay || i <= stage) ? '100%' : '0%';
    });
  }
  function update(next) {
    const nextSignature = JSON.stringify([next.event_id, next.stages, next.receipt, next.evidence]);
    if (signature && signature !== nextSignature) replay = false;
    signature = nextSignature; model = next; lastDelivery = performance.now();
    const arrival = model.receipt && priorEvent === model.event_id && !priorReceipt && !model.simulated && healthy();
    paintText();
    if (arrival && !reduced.matches) {const el=root.querySelector('.receipt');el.classList.remove('is-new');
      void el.offsetWidth;el.classList.add('is-new');}
    priorEvent = model.event_id; priorReceipt = model.receipt;
    draw(); start();
  }
  function project(x,y,z,spin=visualTime*.17){const c=Math.cos(spin),s=Math.sin(spin);const xx=x*c+z*s,zz=-x*s+z*c;const tilt=-.23;const yy=y*Math.cos(tilt)-zz*Math.sin(tilt),z2=y*Math.sin(tilt)+zz*Math.cos(tilt);const size=Math.min(w*.255,h*.265);const f=2.8/(2.8-z2*.27);return {x:w*.5+xx*size*f,y:h*.455+yy*size*f,z:z2,f};}
  function path(points,color,alpha=1,width=1){ctx.strokeStyle=color;ctx.globalAlpha=alpha;ctx.lineWidth=width;ctx.beginPath();points.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.stroke();ctx.globalAlpha=1;}
  function dot(p,r,color,alpha=1,glow=0){ctx.globalAlpha=alpha;ctx.fillStyle=color;if(glow){ctx.shadowColor=color;ctx.shadowBlur=glow;}ctx.beginPath();ctx.arc(p.x,p.y,r,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;ctx.globalAlpha=1;}
  function route(t,side){const start=side==='in'?{x:w*.045,y:h*.57}:{x:w*.51,y:h*.43};const end=side==='in'?{x:w*.48,y:h*.43}:{x:w*.955,y:h*.57};const bend=-Math.sin(t*Math.PI)*h*.16;return {x:start.x+(end.x-start.x)*t,y:start.y+(end.y-start.y)*t+bend};}
  function draw(){
    if(!w||!ctx)return;ctx.clearRect(0,0,w,h);const energy=appearance.energy/100,cx=w*.5,cy=h*.455,r=Math.min(w*.255,h*.265);
    const glow=ctx.createRadialGradient(cx,cy,r*.1,cx,cy,r*2.0);glow.addColorStop(0,'rgba(70,132,236,'+(.08+.15*energy)+')');glow.addColorStop(.5,'rgba(82,94,222,'+(.02+.055*energy)+')');glow.addColorStop(1,'rgba(82,94,222,0)');ctx.fillStyle=glow;ctx.fillRect(0,0,w,h);
    for(let i=0;i<34;i++){const x=(Math.sin(i*98.8)*.5+.5)*w,y=(Math.cos(i*63.4)*.5+.5)*(h*.66)+h*.12;const drift=Math.sin(visualTime*.12+i)*5;dot({x:x+drift,y},.6,colors.a,.15+Math.sin(i+visualTime*.3)*.055);}
    for(let lat=-3;lat<=3;lat++){const phi=lat*Math.PI/9;const points=[];for(let j=0;j<=72;j++){const a=j/72*Math.PI*2;points.push(project(Math.cos(phi)*Math.cos(a),Math.sin(phi),Math.cos(phi)*Math.sin(a)));}path(points,colors.a,.1,0.65);}
    for(let lon=0;lon<7;lon++){const a=lon*Math.PI/7;const points=[];for(let j=0;j<=72;j++){const t=j/72*Math.PI*2;points.push(project(Math.cos(t)*Math.cos(a),Math.sin(t),Math.cos(t)*Math.sin(a)));}path(points,colors.b,.105,0.7);}
    const dots=[];for(let i=0;i<290;i++){const y=1-(i/(289))*2,rad=Math.sqrt(1-y*y),angle=i*2.39996323;const p=project(rad*Math.cos(angle),y,rad*Math.sin(angle));dots.push({...p,index:i});}dots.sort((a,b)=>a.z-b.z);dots.forEach(p=>{const front=(p.z+1)/2;dot(p,(.65+front*.75)*(w<400?.88:1),p.index%13===0?colors.b:colors.a,.15+front*.66);});
    for(let orbit=0;orbit<3;orbit++){const points=[];for(let j=0;j<=100;j++){const a=j/100*Math.PI*2;const tilt=.4+orbit*.7;const rr=1.26+orbit*.08;points.push(project(rr*Math.cos(a),rr*Math.sin(a)*Math.sin(tilt),rr*Math.sin(a)*Math.cos(tilt),visualTime*.08+orbit*1.05));}path(points,orbit===1?colors.b:colors.a,.22,orbit===1?.8:.6);const head=(visualTime*(.1+orbit*.012)+orbit*.32)%1;for(let j=0;j<(appearance.trails?18:1);j++){const phase=(head-j*.002+1)%1,a=phase*Math.PI*2,tilt=.4+orbit*.7,rr=1.26+orbit*.08;const p=project(rr*Math.cos(a),rr*Math.sin(a)*Math.sin(tilt),rr*Math.sin(a)*Math.cos(tilt),visualTime*.08+orbit*1.05);dot(p,j===0?2:1.1,orbit===1?colors.b:colors.a,(1-j/18)*(.45+.3*energy),j===0?10:0);}}
    ['in','out'].forEach(side=>{const points=[];for(let k=0;k<=64;k++)points.push(route(k/64,side));path(points,colors.a,.18,.7);});
    const side=stage<2?'in':'out';const duration=stage===1?2.3:3.4;const packet=(visualTime/duration)%1;
    if(replay && healthy()){for(let j=0;j<(appearance.trails?16:1);j++){const t=Math.max(0,packet-j*.008),p=route(t,side);dot(p,j===0?2.4:1.35,stage===0?colors.hot:colors.a,(1-j/16)*.95,j===0?13:0);}}
    if(stage===1){const sweep=(Math.sin(visualTime*.95)*.82),rr=Math.sqrt(1-sweep*sweep);const scan=[];for(let j=0;j<=80;j++){const a=j/80*Math.PI*2;scan.push(project(rr*Math.cos(a),sweep,rr*Math.sin(a)));}ctx.shadowColor=colors.a;ctx.shadowBlur=10;path(scan,colors.a,.7,1.2);ctx.shadowBlur=0;}
    if(stage===3){const age=replay?Math.max(0,elapsed-11.5):3;const pulse=Math.min(1,age/2.5);if(pulse<1&&!reduced.matches){const ring=[];for(let j=0;j<=90;j++){const a=j/90*Math.PI*2;ring.push({x:cx+Math.cos(a)*r*(1+pulse*1.2),y:cy+Math.sin(a)*r*(1+pulse*1.2)*.7});}path(ring,colors.a,(1-pulse)*.6,1);}dot({x:cx,y:cy},3,colors.a,.9,20);}
    dot(route(0,'in'),2,colors.hot,.8,8);dot(route(1,'out'),2,stage>=2?colors.a:colors.b,stage>=2?.9:.4,stage>=2?9:0);
  }
  function frame(now) {
    raf=0;if(disposed || !root.isConnected || stopped())return;
    if(!last)last=now;const delta=Math.min((now-last)/1000,.08);last=now;visualTime+=delta;
    if(replay){const previous=stage;elapsed=Math.min(15,elapsed+delta);stage=replayStage();
      if(stage!==previous)paintText();if(elapsed>=15){replay=false;paintText();}}
    if(now-lastPaint>32){draw();lastPaint=now;}raf=requestAnimationFrame(frame);
  }
  function start(){if(!raf && !stopped() && !disposed){last=0;raf=requestAnimationFrame(frame);}}
  function stop(){cancelAnimationFrame(raf);raf=0;last=0;}
  pauseButton.onclick=()=>{paused=!paused;remember();paintText();if(paused)stop();else start();};
  replayButton.onclick=()=>{if(!model.replay||!healthy()||reduced.matches)return;replay=!replay;elapsed=0;
    if(replay)paused=false;remember();paintText();draw();start();};
  const onVisibility=()=>{paintText();if(stopped())stop();else start();};
  const onReduced=()=>{if(reduced.matches){replay=false;stop();}paintText();draw();start();};
  const ro=new ResizeObserver(resize);ro.observe(canvas);
  const observer=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;onVisibility();},{threshold:.03});observer.observe(root);
  document.addEventListener('visibilitychange',onVisibility);reduced.addEventListener('change',onReduced);
  const watchdog=setInterval(()=>{paintText();if(stopped())stop();else start();},1000);
  function dispose(){if(disposed)return;disposed=true;remember();stop();clearInterval(watchdog);ro.disconnect();observer.disconnect();
    document.removeEventListener('visibilitychange',onVisibility);reduced.removeEventListener('change',onReduced);
    pauseButton.onclick=null;replayButton.onclick=null;delete root._defenseMotion;}
  root._defenseMotion={update,dispose};resize();update(data);
  return dispose;
}
