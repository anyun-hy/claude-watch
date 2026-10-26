import Foundation
@main struct IdentityPresentationTests {
    static func main() {
        var count=0
        func check(_ value: @autoclosure () -> Bool,_ text:String) { count += 1; if !value(){fatalError(text)} }
        check(ServiceBrand.endpoint("https://claude.ai/cdn-cgi/trace") == .claude,"Claude endpoint")
        check(ServiceBrand.endpoint("https://api.openai.com/v1/models") == .chatgpt,"API service identity")
        check(ServiceBrand.endpoint("https://1.1.1.1/cdn-cgi/trace") == .cloudflare,"HTTP reference identity")
        check(ServiceBrand.endpoint("stun.cloudflare.com:3478") == .cloudflare,"STUN identity")
        check(ServiceBrand.endpoint("https://cloudflare.com.evil.example") == nil,"suffix boundary")
        check(ServiceBrand.endpoint("https://notchatgpt.com") == nil,"service boundary")
        check(ServiceBrand.provider("Cloudflare, Inc.") == .cloudflare,"known provider")
        check(ServiceBrand.provider("Not Cloudflare") == nil,"no substring branding")
        check(CountryIdentity.code("jp") == "JP","case normalize")
        check(CountryIdentity.code(nil,country:"Japan") == "JP","existing English label")
        check(CountryIdentity.code(nil,country:"美国") == "US","existing Chinese label")
        check(CountryIdentity.code(nil,country:"United States") == "US","US")
        check(CountryIdentity.code(nil,country:"未知") == nil,"unknown never guessed")
        check(CountryIdentity.code("../../jp") == nil,"resource traversal rejected")
        check(CountryIdentity.code("ZZ") == nil,"invalid code rejected")
        check(CountryIdentity.place(["Japan","Tokyo","Tokyo","Cloudflare"]) == "Japan · Tokyo · Cloudflare","duplicate geographies")
        check(CountryIdentity.geoCodes("not JSON").isEmpty,"malformed receipt")
        let raw=#"[{"kind":"geoip","query":"1.1.1.1","status":"complete","data":{"country_code":"au"}},{"kind":"geoip","query":"8.8.8.8","status":"error","data":{"country_code":"us"}}]"#
        check(CountryIdentity.geoCodes(raw)["1.1.1.1"] == "AU","raw source code preserved")
        check(CountryIdentity.geoCodes(raw)["8.8.8.8"] == nil,"failed receipt excluded")
        print("IdentityPresentationTests: \(count) assertions passed")
    }
}
