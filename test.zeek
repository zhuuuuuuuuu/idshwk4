event zeek_init()
{
  local r1=SumStats::Reducer($stream="404.lookup",$apply=set(SumSats::SUM);
  local r2=SumStats::Reducer($stream="all_response.lookup",$apply=set(SumSats::UNIQUE,SumSats::SUM);
  SumStats::create([$name"404",$epoch=10mins,$reducer=set(r1,r2),$ephoch_result(ts:time,key:SumStats::Key,result: SumStats::Result]=
  {
    local r=result["404.lookup"];
    {
      if()
      {   
         print fmt
    }});
  
  }
event http_request(c: connection,version:string,code:count,reason:string)
{
  SumStats::observe("all_response.lookup",[$host=c$id$orig_h],[$str=reason]);
  if(reason == "404")
  {
    SumStats::observe("404.lookup",[$host=c$id$orig_h],[$str=reason]);
    }
  }
  
