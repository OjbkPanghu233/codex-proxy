#include "Test.hpp"
int main() {
    Core::ProxyRules::CidrRuleV4 cidr{};
    assert(Core::ProxyRules::ParseCidrV4("192.168.4.99/24", &cidr));
    assert(Core::ProxyRules::MatchCidrV4(0xc0a80401, cidr));
    assert(!Core::ProxyRules::MatchCidrV4(0xc0a80501, cidr));
    for (auto text : {"1.2.3.4.5/24","1.2.3/24","256.2.3.4/24","1.2.3.4/33"}) assert(!Core::ProxyRules::ParseCidrV4(text,&cidr));
    std::array<uint8_t,16> ipv6{};
    assert(!Core::ProxyRules::ParseIPv6("192.0.2.1::", &ipv6));
    Core::Config c;
    assert(c.Parse(nlohmann::json::parse(R"({"rules":{"routing":{"use_default_private":false,"priority_mode":"number","rules":[{"name":"general","action":"proxy","domains":["*.example.com"],"priority":1},{"name":"port","action":"direct","ports":["8000-9000"],"protocols":["tcp"],"priority":2},{"name":"v6","action":"direct","ip_cidrs_v6":["2001:db8::/32"],"priority":3}]}}})")));
    std::string action, rule;
    assert(c.rules.MatchRouting("Api.Example.Com.","",false,443,"tcp",&action,&rule) && action=="proxy" && rule=="general");
    assert(c.rules.MatchRouting("anything","",false,8080,"tcp",&action,&rule) && action=="direct" && rule=="port");
    assert(!c.rules.MatchRouting("anything","",false,8080,"udp",&action,&rule) && action=="proxy");
    assert(c.rules.MatchRouting("","2001:db8:1234::1",true,443,"tcp",&action,&rule) && action=="direct");
    assert(Core::ProxyRules::MatchDomainPattern(".example.com","example.com"));
    assert(!Core::ProxyRules::MatchDomainPattern(".example.com","badexample.com"));
    assert(!c.Parse(nlohmann::json::parse(R"({"rules":{"routing":{"rules":[{"action":"direct","ip_cidrs_v4":["bad"]}]}}})")));
}
