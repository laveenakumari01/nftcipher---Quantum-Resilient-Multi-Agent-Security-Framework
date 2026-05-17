import React, { useEffect } from 'react';

const PremiumThreatFeed = () => {

  useEffect(() => {
    // Globe Canvas Logic
    const gc = document.getElementById('globe-canvas');
    if(gc){
      const gctx = gc.getContext('2d');
      let gW, gH, angle = 0;
      let requestRef;
      function resizeGlobe(){ gW = gc.width = gc.parentElement.clientWidth; gH = gc.height = 340; }
      resizeGlobe();
      window.addEventListener('resize', resizeGlobe);
      
      const nodes = [
        {lat:40.7,lng:-74,col:'#ff3355'},{lat:51.5,lng:0,col:'#ff3355'},
        {lat:35.7,lng:139,col:'#ffaa00'},{lat:19.4,lng:-99,col:'#ff3355'},
        {lat:-33.9,lng:18.4,col:'#ffaa00'},{lat:55.8,lng:37.6,col:'#ff3355'},
        {lat:1.3,lng:103.8,col:'#00f0ff'},{lat:48.9,lng:2.3,col:'#00ff88'},
        {lat:34.1,lng:-118.2,col:'#ff3355'},{lat:28.6,lng:77.2,col:'#ffaa00'},
        {lat:-23.5,lng:-46.6,col:'#00f0ff'},{lat:59.9,lng:30.3,col:'#ff3355'}
      ];
      
      function latLngTo3D(lat,lng,r){
        const phi=(90-lat)*Math.PI/180;
        const theta=(lng+180)*Math.PI/180;
        return {x:r*Math.sin(phi)*Math.cos(theta),y:r*Math.cos(phi),z:r*Math.sin(phi)*Math.sin(theta)};
      }
      
      function project3D(x,y,z,cx,cy,R){
        const cosA=Math.cos(angle);
        const sinA=Math.sin(angle);
        const rx=x*cosA-z*sinA;
        const rz=x*sinA+z*cosA;
        const scale=1.5;
        const px=cx+rx*scale;
        const py=cy-y*scale;
        const visible=rz>-R*0.2;
        return {px,py,visible,depth:rz};
      }
      
      function drawGlobe(){
        gctx.clearRect(0,0,gW,gH);
        const cx=gW/2; const cy=gH/2-30; const R=110;
        
        const grad=gctx.createRadialGradient(cx,cy,0,cx,cy,R);
        grad.addColorStop(0,'rgba(0,102,255,0.08)');
        grad.addColorStop(0.6,'rgba(0,240,255,0.04)');
        grad.addColorStop(1,'transparent');
        gctx.beginPath(); gctx.arc(cx,cy,R,0,Math.PI*2);
        gctx.fillStyle=grad; gctx.fill();
        
        for(let lat=-60;lat<=60;lat+=30){
          const phi=(90-lat)*Math.PI/180;
          gctx.beginPath();
          let first=true;
          for(let lng=-180;lng<=180;lng+=4){
            const p=latLngTo3D(lat,lng,R);
            const {px,py,visible}=project3D(p.x,p.y,p.z,cx,cy,R);
            if(visible){if(first){gctx.moveTo(px,py);first=false;}else gctx.lineTo(px,py);}
            else first=true;
          }
          gctx.strokeStyle='rgba(0,240,255,0.08)'; gctx.stroke();
        }
        
        for(let lng=0;lng<360;lng+=30){
          gctx.beginPath();
          let first=true;
          for(let lat=-80;lat<=80;lat+=3){
            const p=latLngTo3D(lat,lng,R);
            const {px,py,visible}=project3D(p.x,p.y,p.z,cx,cy,R);
            if(visible){if(first){gctx.moveTo(px,py);first=false;}else gctx.lineTo(px,py);}
            else first=true;
          }
          gctx.strokeStyle='rgba(0,240,255,0.06)'; gctx.stroke();
        }
        
        nodes.forEach((n,i)=>{
          const p=latLngTo3D(n.lat,n.lng,R);
          const {px,py,visible,depth}=project3D(p.x,p.y,p.z,cx,cy,R);
          if(!visible) return;
          const t=Date.now()/1000;
          const pulse=Math.sin(t*2+i)*0.3+0.7;
          gctx.beginPath();
          gctx.arc(px,py,4*pulse,0,Math.PI*2);
          gctx.fillStyle=n.col; gctx.fill();
          gctx.beginPath();
          gctx.arc(px,py,10*pulse,0,Math.PI*2);
          gctx.strokeStyle=n.col+'66'; gctx.lineWidth=1; gctx.stroke();
        });
        
        const arcs=[[0,1],[1,2],[0,3],[4,5],[6,7],[8,0],[2,9]];
        arcs.forEach(([a,b])=>{
          const pa=latLngTo3D(nodes[a].lat,nodes[a].lng,R);
          const pb=latLngTo3D(nodes[b].lat,nodes[b].lng,R);
          const da=project3D(pa.x,pa.y,pa.z,cx,cy,R);
          const db=project3D(pb.x,pb.y,pb.z,cx,cy,R);
          if(!da.visible||!db.visible) return;
          const midX=(da.px+db.px)/2;
          const midY=(da.py+db.py)/2-40;
          gctx.beginPath();
          gctx.moveTo(da.px,da.py);
          gctx.quadraticCurveTo(midX,midY,db.px,db.py);
          gctx.strokeStyle=nodes[a].col+'44';
          gctx.lineWidth=1;
          gctx.setLineDash([4,6]);
          gctx.stroke();
          gctx.setLineDash([]);
        });
        
        angle+=0.004;
        requestRef = requestAnimationFrame(drawGlobe);
      }
      requestRef = requestAnimationFrame(drawGlobe);

      return () => {
        window.removeEventListener('resize', resizeGlobe);
        cancelAnimationFrame(requestRef);
      };
    }
  }, []);

  useEffect(() => {
    // Feed logic
    const threats=['SQL injection attempt','Ransomware C2 beacon','Credential stuffing attack','XSS payload injection','Zero-day exploit attempt','DNS tunneling detected','Brute force login','Malware download blocked','Reverse shell attempt','Insider data exfil'];
    const severities=[{cls:'sv-c',badge:'sb-c',txt:'CRITICAL'},{cls:'sv-h',badge:'sb-h',txt:'HIGH'},{cls:'sv-m',badge:'sb-m',txt:'MEDIUM'}];
    const ips=['10.0.0.','192.168.1.','172.16.0.','203.0.113.'];
    
    const interval = setInterval(()=>{
      const feed=document.getElementById('feed-list');
      if(!feed) return;
      const sev=severities[Math.floor(Math.random()*severities.length)];
      const threat=threats[Math.floor(Math.random()*threats.length)];
      const ip=ips[Math.floor(Math.random()*ips.length)]+(Math.floor(Math.random()*255));
      const div=document.createElement('div');
      div.className='feed-item'; div.style.opacity='0'; div.style.transform='translateX(-20px)'; div.style.transition='all 0.4s';
      div.innerHTML=`<div class="sev-dot ${sev.cls}"></div><div class="feed-text"><div class="feed-name"><span class="sev-badge ${sev.badge}">${sev.txt}</span>${threat}</div><div class="feed-meta">${ip} · Just now</div></div>`;
      feed.insertBefore(div,feed.firstChild);
      setTimeout(()=>{div.style.opacity='1';div.style.transform='translateX(0)'},50);
      while(feed.children.length>8) feed.removeChild(feed.lastChild);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  return (
    <section className="threat-section">
  <div className="container">
    <div className="sec-header reveal">
      <div className="sec-tag">Live Intelligence</div>
      <h2 className="sec-title">Global threat map.<br />Your posture, <em>live.</em></h2>
    </div>
    <div className="threat-grid">
      <div className="threat-panel reveal">
        <div className="panel-header">
          <span className="panel-title">Threat Feed</span>
          <span className="live-badge">Live</span>
        </div>
        <div id="feed-list">
          <div className="feed-item"><div className="sev-dot sv-c"></div><div className="feed-text"><div className="feed-name"><span className="sev-badge sb-c">CRITICAL</span>SQL injection attempt</div><div className="feed-meta">192.168.1.44 → api-prod-02 · 2s ago</div></div></div>
          <div className="feed-item"><div className="sev-dot sv-h"></div><div className="feed-text"><div className="feed-name"><span className="sev-badge sb-h">HIGH</span>Privilege escalation detected</div><div className="feed-meta">svc_monitor · k8s-node-07 · 11s ago</div></div></div>
          <div className="feed-item"><div className="sev-dot sv-c"></div><div className="feed-text"><div className="feed-name"><span className="sev-badge sb-c">CRITICAL</span>Lateral movement blocked</div><div className="feed-meta">10.0.0.8 → 10.0.0.19 · Quarantined</div></div></div>
          <div className="feed-item"><div className="sev-dot sv-m"></div><div className="feed-text"><div className="feed-name"><span className="sev-badge sb-m">MEDIUM</span>Unusual login location</div><div className="feed-meta">admin@acme.com · Lagos, NG · 1m ago</div></div></div>
          <div className="feed-item"><div className="sev-dot sv-h"></div><div className="feed-text"><div className="feed-name"><span className="sev-badge sb-h">HIGH</span>Data exfiltration attempt</div><div className="feed-meta">db-replica-3 → 203.0.113.7 · Blocked</div></div></div>
          <div className="feed-item"><div className="sev-dot sv-l"></div><div className="feed-text"><div className="feed-name"><span className="sev-badge sb-l">LOW</span>Port scan detected</div><div className="feed-meta">External 45.33.32.156 · 3m ago</div></div></div>
        </div>
      </div>
      <div className="globe-panel reveal reveal-d2">
        <div className="panel-header" style={{"position":"relative","zIndex":"3"}}>
          <span className="panel-title">Global Attack Map</span>
          <span className="live-badge">Real-time</span>
        </div>
        <canvas id="globe-canvas" style={{"height":"340px"}}></canvas>
        <div className="globe-overlay-stats">
          <div><div className="gstat-val danger">2,847</div><div className="gstat-label">Active Threats</div></div>
          <div><div className="gstat-val safe">2,844</div><div className="gstat-label">Blocked Today</div></div>
          <div><div className="gstat-val">48</div><div className="gstat-label">Countries</div></div>
          <div><div className="gstat-val" style={{"color":"var(--cyan)"}}>0.38s</div><div className="gstat-label">Avg MTTR</div></div>
        </div>
      </div>
    </div>
  </div>
</section>
  );
};

export default PremiumThreatFeed;
