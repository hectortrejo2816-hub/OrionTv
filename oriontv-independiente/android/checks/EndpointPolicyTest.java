import com.oriontv.independent.EndpointPolicy;
import java.util.*;
public class EndpointPolicyTest {
 static void check(boolean value){if(!value)throw new AssertionError();}
 public static void main(String[] args){
  List<String> values=EndpointPolicy.parse("https://one.invalid/,https://one.invalid,https://two.invalid:8443,https://three.invalid",true);
  check(values.size()==3);check(values.get(0).equals("https://one.invalid"));
  check(EndpointPolicy.parse("http://one.invalid,https://user:pass@two.invalid,https://three.invalid?key=secret,https://four.invalid:0,https://five.invalid:70000",true).isEmpty());
  check(EndpointPolicy.parse("http://one.invalid:8080",false).size()==1);
  check(EndpointPolicy.prefer(values,"https://two.invalid:8443").get(0).equals("https://two.invalid:8443"));
  check(EndpointPolicy.prefer(values,"https://untrusted.invalid").equals(values));
  check(EndpointPolicy.parse("https://a.invalid,https://b.invalid,https://c.invalid,https://d.invalid,https://e.invalid",true).size()==4);
  for(int code:new int[]{401,403,404,409,429})check(!EndpointPolicy.retryStatus(code));
  for(int code:new int[]{408,502,503,504})check(EndpointPolicy.retryStatus(code));
  System.out.println("EndpointPolicy: all checks passed");
 }
}
