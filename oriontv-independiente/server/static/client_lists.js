'use strict';
function attachClientLists(license){
 const host=document.querySelector('.modal #client-lists');if(!host)return;
 if(!license.id){host.textContent='Guarda primero el cliente para añadir sus listas IPTV.';return;}
 let items=[],busy=false,primary=null;
 const title=document.createElement('h3');title.textContent='Listas IPTV';
 const note=document.createElement('p');note.textContent='Hasta 5 listas por cliente. En la app aparecen solamente sus nombres.';
 const main=document.createElement('p'),rows=document.createElement('div'),status=document.createElement('p');status.setAttribute('role','status');
 const add=document.createElement('button');add.type='button';add.className='secondary';add.textContent='+ Añadir lista';
 const save=document.createElement('button');save.type='button';save.className='primary';save.textContent='Guardar listas';
 host.replaceChildren(title,note,main,rows,add,save,status);
 async function request(method,body){const r=await fetch('/api/admin/licenses/'+encodeURIComponent(license.id)+'/playlists',{method,credentials:'same-origin',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const result=await r.json();if(!r.ok)throw Error(typeof result.detail==='string'?result.detail:'No se pudieron guardar las listas');return result;}
 function draw(){rows.replaceChildren();items.forEach((item,index)=>{const box=document.createElement('fieldset');box.disabled=busy;const legend=document.createElement('legend');legend.textContent='Lista '+(index+2);box.append(legend);
 const label=document.createElement('label');label.textContent='DNS autorizado';const select=document.createElement('select');const empty=document.createElement('option');empty.value='';empty.textContent='Selecciona una lista';select.append(empty);
 for(const dns of data.dns){if(dns.id===primary.dns_id)continue;const option=document.createElement('option');option.value=dns.id;option.textContent=dns.name;select.append(option);}select.value=item.dns_id||'';select.onchange=()=>{item.dns_id=select.value;if(!item.name)item.name=(data.dns.find(d=>d.id===select.value)||{}).name||'';draw();};label.append(select);box.append(label);
 for(const [text,key,type] of [['Nombre que verá el cliente','name','text'],['Usuario del servicio','service_user','text'],[item.id?'Contraseña (vacía para conservar)':'Contraseña del servicio','service_password','password']]){const label=document.createElement('label');label.textContent=text;const field=document.createElement('input');field.type=type;field.value=item[key]||'';field.autocomplete=type==='password'?'new-password':'off';field.maxLength=key==='name'?80:key==='service_user'?128:256;field.oninput=()=>{item[key]=field.value;};label.append(field);box.append(label);}
 const remove=document.createElement('button');remove.type='button';remove.className='secondary';remove.textContent='Quitar lista';remove.onclick=()=>{items.splice(index,1);draw();};box.append(remove);rows.append(box);});add.disabled=busy||items.length>=4;save.disabled=busy;title.textContent='Listas IPTV · '+(items.length+1)+' / 5';}
 async function load(){busy=true;add.disabled=save.disabled=true;status.textContent='Cargando listas…';try{const result=await request('GET');if(!host.isConnected)return;primary=result.primary;items=result.playlists;main.textContent='Principal: '+primary.name+' · Se modifica con el DNS del cliente.';status.textContent='';}catch(e){status.textContent=e.message;}finally{busy=false;if(primary)draw();}}
 add.onclick=()=>{if(busy||items.length>=4)return;items.push({dns_id:'',name:'',service_user:'',service_password:''});draw();};
 save.onclick=async()=>{if(busy||!primary)return;const form=host.closest('form');if(form.elements.dns_id.value!==primary.dns_id){status.textContent='Guarda primero el cambio del DNS principal y vuelve a abrir el cliente.';return;}if(items.some(i=>!i.dns_id||!i.service_user||(!i.id&&!i.service_password))){status.textContent='Completa DNS, usuario y contraseña de cada lista nueva.';return;}busy=true;draw();status.textContent='Guardando listas…';try{await request('PUT',{playlists:items});await load();if(host.isConnected)status.textContent='Listas guardadas. La app las recibirá al sincronizar.';}catch(e){status.textContent=e.message;}finally{busy=false;draw();}};
 load();
}
