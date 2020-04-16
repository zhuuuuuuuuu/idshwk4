event zeek_init()
{
  local r1=SumStats::Reducer($stream="404.lookup",$apply=set(SumSats::SUM);
  local r2=SumStats::Reducer($stream="all_response.lookup",$apply=set(SumSats::UNIQUE,SumSats::SUM);
  SumStats::create([$name"404",
                    $epoch=10min,
                    $reducer=set(r1,r2),
                    $ephoch_result(ts:time,key:SumStats::Key,result: SumStats::Result]=
  {
    local r3=result["404.lookup"];
    local r4=result["all_response.lookup"];
    if(r3$num>2)
    {   
        print fmt("%s is a scanner with %d scan attempts on %d urls", key$host,r3$num
        }
    }]);
  
  }
event http_reply(c: connection,version:string,code:count,reason:string)
{
  SumStats::observe("all_response.lookup",[$num=count]);//统计all_response
  if(reason == "404")//统计所有404的
  {
    SumStats::observe("404.lookup",[$host=c$id$orig_h],[$str=reason]);
    }
  }
  
