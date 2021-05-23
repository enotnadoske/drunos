#include "Retic.hh"

#include <chrono>

#include "Controller.hh"
#include "Common.hh"
#include "oxm/openflow_basic.hh"
#include "retic/applier.hh"
#include "retic/fdd.hh"
#include "retic/fdd_compiler.hh"
#include "retic/fdd_translator.hh"
#include "retic/traverse_fdd.hh"
#include "retic/tracer.hh"
#include "retic/leaf_applier.hh"
#include "retic/trace_tree.hh"
#include "PacketParser.hh"

#define PRIO_HIGH 65535

REGISTER_APPLICATION(Retic, {"controller", ""})

using namespace runos;

using secs = std::chrono::seconds;

void Retic::init(Loader* loader, const Config& root_config)
{
    this->registerPolicy("__builtin_donothing__", retic::stop());
    auto ctrl = Controller::get(loader);

    ctrl->registerHandler<of13::PacketIn>([=](of13::PacketIn& pi, SwitchConnectionPtr conn) {
        DVLOG(10) << "PacketIn";

        PacketParser pp{pi, conn->dpid()};

        retic::fdd::Traverser traverser(pp, m_backend.get());
        auto& leaf = boost::apply_visitor(traverser, m_fdd);

        std::vector<oxm::field_set> sets;
        sets.reserve(sets.size());
        for (auto& s: leaf.sets) {
            if (s.body.has_value()) {
                throw std::runtime_error("There must not be leaf with handler");
            }
            sets.push_back(s.pred_actions);
        }
        m_backend->packetOuts(static_cast<uint8_t*>(pi.data()), pi.data_len(), sets, conn->dpid());
    });

    m_table = ctrl->getTable("retic");
    Config config = config_cd(root_config, "retic");
    m_main_policy = config_get(config, "main", "__builtin_donothing__");
    LOG(INFO) << "Main policy: " << m_main_policy;


    QObject::connect(ctrl, &Controller::switchUp, this, &Retic::onSwitchUp);
}

void Retic::startUp(Loader* loader) {
    try {
        m_fdd = retic::fdd::compile(m_policies.at(m_main_policy));
    } catch (std::out_of_range& oor) {
        LOG(ERROR) << "Can't find policy " << m_main_policy;
        // TODO: throw more properly exception
        throw std::runtime_error("Couldn't find main policy");
    }
}

void Retic::registerPolicy(std::string name, retic::policy policy) {
    LOG(INFO) << "Register policy: " << name;
    m_policies[name] = policy;
}

void Retic::onSwitchUp(SwitchConnectionPtr conn, of13::FeaturesReply fr) {
    m_backend = nullptr;
    m_drivers[conn->dpid()] = makeDriver(conn);
    this->reinstallRules();
}

std::vector<std::string> Retic::getPoliciesName() const {
    std::vector<std::string> ret;
    ret.reserve(m_policies.size());
    for (const auto& [name, pol]: m_policies) {
        ret.push_back(name);
    }
    return ret;
}

void Retic::clearRules() {
    m_backend = nullptr;
}

void Retic::reinstallRules() {
    m_backend = std::make_unique<Of13Backend>(m_drivers, m_table);
    m_fdd = retic::fdd::compile(m_policies.at(m_main_policy));
    retic::fdd::Translator translator(*m_backend);
    boost::apply_visitor(translator, m_fdd);
}

void Retic::setMain(std::string new_main) {
    m_main_policy = new_main;
    m_fdd = retic::fdd::compile(m_policies[m_main_policy]);
    this->reinstallRules();
}

namespace runos {

using link_pair = std::pair<std::pair<uint64_t,uint64_t>,std::pair<uint64_t,uint64_t>>;
std::map<link_pair, std::vector<std::pair<oxm::field_set, uint64_t>>> link_tag;

bool intersects(oxm::field_set m1, oxm::field_set m2){
    for(auto it : m1){
        auto tmp = m2.find(it.type());
        if((tmp) != m2.end()){
            if (it != *tmp){
                return false;
            }
        }
    }
    return true;
}

uint64_t getTag(oxm::field_set match, oxm::switch_id id1, oxm::out_port outport, oxm::switch_id id2, oxm::in_port inport){
    oxm::field_set tmp1;
    oxm::field_set tmp2;
    tmp1.modify(oxm::field<>(id1));
    tmp1.modify(oxm::field<>(outport));
    tmp2.modify(oxm::field<>(id2));
    tmp2.modify(oxm::field<>(inport));
    uint64_t sw1,sw2,iport,oport;
    Packet& pkt1(tmp1);
    Packet& pkt2(tmp2);
    sw1 = pkt1.load(oxm::switch_id());
    oport = pkt1.load(oxm::out_port());
    sw2 = pkt2.load(oxm::switch_id());
    iport = pkt2.load(oxm::in_port());
    link_pair lnk({sw1,oport},{sw2,iport});
    auto m_tags = link_tag[lnk];
    std::vector<uint64_t> used_tags;
    if(!m_tags.empty())
        for (auto it : m_tags){
            if (intersects(it.first, match)){
                used_tags.push_back(it.second);
            }
        }
    std::sort(used_tags.begin(),used_tags.end());
    uint64_t prev = 1;
    for (auto it : used_tags){
        if (it == prev){prev++;};
        if (it > prev){break;}
    }
    link_tag[lnk].push_back(std::pair(match, prev));
    return prev;
}


// TODO: remove code duplication of switch detection in install and installBarrier method

void Of13Backend::install(
    oxm::field_set match,
    std::vector<oxm::field_set> actions,
    uint16_t prio,
    retic::FlowSettings flow_settings
) {
    if (flow_settings.hard_timeout == retic::duration::zero()) {
        // there is no need to install its flow, becouse timeouts is zero
        return;
    }
    static const auto ofb_switch_id = oxm::switch_id();
    static const auto ofb_route_id = oxm::route();
    std::vector<retic::route_t> routes;
    std::map<uint64_t, oxm::field_set> rt_act;
    
    for(uint64_t i = 0; i < actions.size(); i++){
        auto route_id_it = actions[i].find(oxm::type(ofb_route_id));//get route id also
        if (route_id_it != match.end()) {
            Packet& pkt_iface(match);
            uint64_t rt_id = pkt_iface.load(ofb_route_id);
            actions[i].erase(oxm::mask<>(ofb_route_id));
            auto cur_route = retic::route_ids[rt_id];
            routes.push_back(cur_route);
            if(cur_route.first.type == 2 && !cur_route.second.empty()){
                match.modify(oxm::field<>(cur_route.first.sw_id));
                oxm::field_set tmp;
                tmp.modify(oxm::field<>(cur_route.first.outport));
                rt_act[rt_id] = actions[i];

                actions[i] = tmp;
            }else{
                actions[i].modify(oxm::field<>(cur_route.first.outport));
            }
            //first dpid actions changed if route
            //first switch in route
                //match get more from route
                //actions create from route
            //middle route switches
                //match get more from route
                //actions create from route
            //last switch in route
                //match get more from route
                //actions create from route
        }
    }
    auto switch_id_it = match.find(oxm::type(ofb_switch_id));
    if (switch_id_it != match.end()) {
        Packet& pkt_iface(match);
        uint64_t dpid = pkt_iface.load(ofb_switch_id);
        match.erase(oxm::mask<>(ofb_switch_id));
        install_on(dpid, match, actions, prio, flow_settings);
    } else {
        for (auto [dpid, driver]: m_drivers) {
            install_on(dpid, match, actions, prio, flow_settings);
        }
    }
    if(!rt_act.empty()){
        for(auto it : rt_act){
            auto rtt = retic::route_ids[it.first];
            for(uint64_t it2 = 0; it2 < rtt.second.size()-1; it2++){
                auto sw = rtt.second[it2].sw_id;
                auto inport = rtt.second[it2].inport;
                auto outport = rtt.second[it2].outport;
                match.modify(oxm::field<>(sw));
                match.modify(oxm::field<>(inport));
                oxm::field_set tm;
                tm.modify(oxm::field<>(outport));
                std::vector<oxm::field_set> t;
                t.push_back(tm);
                Packet& pkt_inface(match);
                uint64_t dpid = pkt_inface.load(ofb_switch_id);
                match.erase(oxm::mask<>(ofb_switch_id));
                uint16_t p = PRIO_HIGH;
                install_on(dpid, match, t, p, flow_settings);

            }
            auto sw = rtt.second[rtt.second.size()-1].sw_id;
            auto inport = rtt.second[rtt.second.size()-1].inport;
            auto outport = rtt.second[rtt.second.size()-1].outport;
            match.modify(oxm::field<>(sw));
            match.modify(oxm::field<>(inport));
            it.second.modify(oxm::field<>(outport));
            Packet& pkt_inface(match);
            uint64_t dpid = pkt_inface.load(ofb_switch_id);
            match.erase(oxm::mask<>(ofb_switch_id));
            uint16_t k = PRIO_HIGH;
            install_on(dpid, match, std::vector<oxm::field_set>{it.second}, k, flow_settings);

        }
    }
}

void Of13Backend::installBarrier(oxm::field_set match, uint16_t prio) {
    static const auto ofb_switch_id = oxm::switch_id();
    auto switch_id_it = match.find(oxm::type(ofb_switch_id));
    Actions act;
    act.out_port = ports::to_controller;

    if (switch_id_it != match.end()) {
        Packet& pkt_iface(match);
        uint64_t dpid = pkt_iface.load(ofb_switch_id);
        match.erase(oxm::mask<>(ofb_switch_id));
        auto driver_it = m_drivers.find(dpid);
        if (driver_it == m_drivers.end()) {
            LOG(WARNING) << "Needed to install rule. But there is no such switch";
            return;
        }
        auto flow = driver_it->second->installRule(match, prio, act, m_table);
        m_storage.push_back(flow);
    } else {
        for (auto [dpid, driver]: m_drivers) {
            auto flow = driver->installRule(match, prio, act, m_table);
            m_storage.push_back(flow);
        }
    }
}

void Of13Backend::packetOuts(uint8_t* data, size_t data_len, std::vector<oxm::field_set> actions, uint64_t dpid) {
    static const auto ofb_out_port = oxm::out_port();
    static const auto ofb_route_id = oxm::route();
    auto driver = m_drivers.at(dpid);
    if (actions.empty()) {
        return;
    }
    for (auto& action: actions) {
        Actions driver_acts{};
        auto out_port_it = action.find(oxm::type(ofb_route_id));
        if (out_port_it != action.end()) {
            Packet& pkt_iface(action);
            uint32_t out_port = pkt_iface.load(ofb_route_id);
            action.erase(oxm::mask<>(ofb_out_port));
            auto rt = retic::route_ids[out_port];
            oxm::field_set a;
            a.modify(oxm::field<>(rt.first.outport));
            Packet& pkt(a);
            uint32_t op = pkt.load(ofb_out_port);
            driver_acts.out_port = op;
            driver_acts.set_fields = action;
            driver->packetOut(data, data_len, driver_acts);
        }
    }
}

void Of13Backend::install_on(
    uint64_t dpid,
    oxm::field_set match,
    std::vector<oxm::field_set> actions,
    uint16_t prio,
    retic::FlowSettings settings
) {
    using namespace retic;
    static const auto ofb_out_port = oxm::out_port();
    auto driver_it = m_drivers.find(dpid);
    if (driver_it == m_drivers.end()) {
        LOG(WARNING) << "Needed to install rule. But there is no such switch";
        return;
    }

    OFDriverPtr driver = driver_it->second;

    if (actions.empty()) {
        // drop packet
        driver->installRule(match, prio, {}, m_table);
        return;
    } 
    std::vector<Actions> buckets;
    buckets.reserve(actions.size());
    for (auto& action: actions) {
        Actions driver_acts{};
        driver_acts.idle_timeout =
            settings.idle_timeout == duration::max() ? 0 : secs(settings.idle_timeout).count();
        driver_acts.hard_timeout =
            settings.hard_timeout == duration::max() ? 0 : secs(settings.hard_timeout).count();
        auto out_port_it = action.find(oxm::type(ofb_out_port));
        if (out_port_it != action.end()) {
            Packet& pkt_iface(action);
            uint32_t out_port = pkt_iface.load(ofb_out_port);
            action.erase(oxm::mask<>(ofb_out_port));
            driver_acts.out_port = out_port;
            driver_acts.set_fields = action;
            buckets.push_back(driver_acts);
        }
    }

    if (buckets.empty()) {
        // install drop rule
        auto flow = driver->installRule(match, prio, {}, m_table);
        m_storage.push_back(flow);
    } else if(buckets.size() == 1) {
        // one actoinlist install directly into flow
        auto flow = driver->installRule(match, prio, buckets[0], m_table);
        m_storage.push_back(flow);
    } else {
        // many actionlists, create Group

        auto group = driver->installGroup(GroupType::All, buckets);
        m_storage.push_back(group);
        Actions to_group = {.group_id = group->id()};
        auto flow = driver->installRule(match, prio, to_group, m_table);
        m_storage.push_back(flow);
    }
}

} // namespace runos
