@load base/frameworks/sumstats
event zeek_init()
{
  local r1=SumStats::Reducer($stream="404.lookup",$apply=set(SumStats::UNIQUE));
  local r2=SumStats::Reducer($stream="all_response.lookup",$apply=set(SumStats::UNIQUE));
  SumStats::create([$name="scan.lookup",
                    $epoch=10mins,
                    $reducers=set(r1,r2),
                    $ephoch_result(ts:time, key:SumStats::Key, result: SumStats::Result)  =
					          {
					                	local r3 = result["404.lookup"];
    						            local r4 = result["all_response.lookup"];
    						            if(r3$num>2 && (r3$num/r4$num)>0.2 
    						            && (r3$unique/r3$num)> 0.5 )
    						            {   
    							              print fmt("%s is a scanner with %d scan attempts on %d urls",
    							              key$host,r3$num,r3$unique);
    						             }
					 }]);
}
  
event http_reply(c: connection,version:string,code:count,reason:string)
{
  SumStats::observe("all_response.lookup",[$host=c$id$orig_h],[$str=c$http$uri]);
  if(code == 404)
   {
    SumStats::observe("404.lookup",[$host=c$id$orig_h],[$str=c$http$uri]);
    }
}
