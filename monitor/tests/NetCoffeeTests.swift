import Foundation

@main struct NetCoffeeTests {
    static func main() throws {
        var count=0
        func check(_ ok: @autoclosure () -> Bool, _ message:String) { count += 1; if !ok(){fatalError(message)} }
        let path=CommandLine.arguments[1], bytes=try Data(contentsOf:URL(fileURLWithPath:path))
        let receipt=try JSONDecoder().decode(CoffeeReceipt.self,from:bytes)
        check(receipt.score == 41,"raw source score")
        check(receipt.httpStatus == 200,"HTTP preserved")
        check(receipt.data?["is_vpn"]?.flag == false,"false != missing")
        check(receipt.data?["missing"]?.flag == nil,"missing != false")
        check(receipt.data?["asn"]?.number == 13335,"ASN")
        check(receipt.data?["geo_sources"] != nil,"nested geo retained")
        check(receipt.raw.contains("related_domains"),"raw data retained")
        var object=try JSONSerialization.jsonObject(with:bytes) as! [String:Any]
        var data=object["data"] as! [String:Any]
        for value in [-1,101,41.5,"41",NSNull(),true] as [Any] {
            data["trust_score"]=value;object["data"]=data
            let r=try JSONDecoder().decode(CoffeeReceipt.self,from:JSONSerialization.data(withJSONObject:object))
            check(r.score == nil,"invalid score must stay unavailable")
        }
        data["trust_score"]=41; data["ip"]="8.8.8.8";object["data"]=data
        let mismatch=try JSONDecoder().decode(CoffeeReceipt.self,from:JSONSerialization.data(withJSONObject:object)); check(mismatch.score == nil,"response IP mismatch")
        object["status"]="timeout";data["ip"]="1.1.1.1";object["data"]=data
        let timeout=try JSONDecoder().decode(CoffeeReceipt.self,from:JSONSerialization.data(withJSONObject:object)); check(timeout.score == nil,"timeout never valid score")
        // Schema additions remain backward-compatible with original collectors.
        let old=LeakProbeResult(kind:"dns",status:"complete",startedAt:1,finishedAt:2,scope:"old",observations:[.init(address:"8.8.8.8",kind:"resolver",source:"old")],errors:[],contextChanged:false,details:[])
        let oldRoundtrip=try JSONDecoder().decode(LeakProbeResult.self,from:JSONEncoder().encode(old)); check(oldRoundtrip.externalJSON == nil,"old receipt compatible")
        let empty=LeakProbeResult(kind:"dns",status:"complete",startedAt:1,finishedAt:2,scope:"coffee",observations:[.init(address:"1.1.1.1",kind:"http",source:"ref")],errors:[],contextChanged:false,details:[])
        check(LeakPolicy.evaluate(empty,kind:.dns,expected:"",now:3).state == .incomplete,"DNS empty never safe")
        print("NetCoffeeTests: \(count) assertions passed")
    }
}
