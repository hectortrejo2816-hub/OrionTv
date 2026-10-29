package com.oriontv.independent;
import java.net.URI;
import java.util.*;
/** Explicit administrator allowlist only; never probes arbitrary ports. */
public final class EndpointPolicy {
 private EndpointPolicy(){}
 public static List<String> parse(String configured,boolean httpsOnly){
  LinkedHashSet<String> out=new LinkedHashSet<>();
  for(String raw:configured.split("[,\\r\\n]+")){
   String value=raw.trim().replaceAll("/+$","");if(value.isEmpty())continue;
   try{URI u=new URI(value);String scheme=u.getScheme();int port=u.getPort();
    if(u.getHost()==null||u.getRawUserInfo()!=null||u.getRawQuery()!=null||u.getRawFragment()!=null||port==0||port>65535||(!"https".equalsIgnoreCase(scheme)&&(!"http".equalsIgnoreCase(scheme)||httpsOnly)))continue;
    out.add(value);if(out.size()==4)break;
   }catch(Exception ignored){}
  }
  return new ArrayList<>(out);
 }
 public static List<String> prefer(List<String> configured,String preferred){List<String> result=new ArrayList<>(configured);if(result.remove(preferred))result.add(0,preferred);return result;}
 public static boolean retryStatus(int code){return code==408||code==502||code==503||code==504;}
}
