#pragma once

#include <functional>
#include <list>
#include <set>
#include <tuple>
#include <chrono>
#include <boost/variant.hpp>
#include <boost/variant/recursive_wrapper_fwd.hpp>
#include <boost/variant/static_visitor.hpp>
#include "api/Packet.hh"
#include "oxm/openflow_basic.hh"
#include <utility>

namespace runos {
namespace retic {
#ifndef TMP
#define TMP
class first_topo_comp;
class topo_comp;
using route_t = std::pair<first_topo_comp,std::vector<topo_comp>>;
inline std::map<uint64_t, route_t> route_ids;// map of all routes and their packet_ids
#endif
typedef std::chrono::duration<uint32_t> duration;

class Filter {
public:
    oxm::field<> field;
};

// static constexpr auto out_port = oxm::out_port();
//     return modify(out_port << port);

class first_topo_comp {//constructor
public:
    uint8_t type;
    oxm::out_port outport;
    oxm::switch_id sw_id;
    oxm::in_port inport;
    first_topo_comp(){};
    first_topo_comp(oxm::out_port op){
        type = 1;
        outport = op;
    }
    first_topo_comp(oxm::in_port in, oxm::switch_id sw, oxm::out_port op){
        type = 2;
        inport = in;
        sw_id = sw;
        outport = op;
    }
    first_topo_comp(const first_topo_comp& a){
        outport = a.outport;
        type = a.type;
        sw_id = a.sw_id;
        inport = a.inport;
    }
};

class topo_comp {//constructor
public:
    oxm::out_port outport;
    oxm::switch_id sw_id;
    oxm::in_port inport;
    topo_comp(){};
    topo_comp(oxm::in_port in, oxm::switch_id sw, oxm::out_port op){
        //type = 2;
        inport = in;
        sw_id = sw;
        outport = op;
    }
    topo_comp(const topo_comp& a){
        outport = a.outport;
        sw_id = a.sw_id;
        inport = a.inport;
    }
};



class Route {//constructor and setting route in map
private:
    route_t route;
    uint64_t route_id;
public:
    Route(){
        std::map <uint64_t, route_t> tmp;
        route_ids = tmp;
    };
    inline
     uint64_t get_route_id(void){return route_id;};
    Route(const first_topo_comp& first, const std::vector<topo_comp>& other){
        route = std::make_pair(first,other);

        route_id = route_ids.size();
        route_ids.insert({route_id,route});
    };
};

class Stop { };

class Id { };

struct Modify {
    oxm::field<> field;
};

struct FlowSettings {
    duration idle_timeout = duration::max();
    duration hard_timeout = duration::max();
    inline friend FlowSettings operator&(const FlowSettings& lhs, const FlowSettings& rhs) {
        FlowSettings ret;
        ret.idle_timeout = std::min(lhs.idle_timeout, rhs.idle_timeout);
        ret.hard_timeout = std::min(lhs.hard_timeout, rhs.hard_timeout);

        // hard timeout cann't be less than idle timeout
        ret.idle_timeout = std::min(ret.idle_timeout, ret.hard_timeout);
        return ret;
    }
};

struct Sequential;
struct Parallel;
struct PacketFunction;
struct Negation;

using policy =
    boost::variant<
        Stop,
        Id,
        Filter,
        Modify,
        FlowSettings,
        boost::recursive_wrapper<Negation>,
        boost::recursive_wrapper<PacketFunction>,
        boost::recursive_wrapper<Sequential>,
        boost::recursive_wrapper<Parallel>
    >;

struct Negation {
    policy pol;
};

struct PacketFunction {
    uint64_t id;
    std::function<policy(Packet& pkt)> function;
};

struct Sequential {
    policy one;
    policy two;
};

struct Parallel {
    policy one;
    policy two;
};

inline
policy modify(oxm::field<> field) {
    return Modify{field};
}

inline
policy fwd_route(Route rt){
    static constexpr auto route = oxm::route();
    return modify(route << rt.get_route_id());
}

inline
policy fwd(uint32_t port) {
    static constexpr auto route = oxm::route();
    first_topo_comp first;
    first.outport << port;
    std::vector<topo_comp> emp;
    auto rt = Route(first, emp);
    uint64_t num = rt.get_route_id();
    
    //create this route
    return modify(route << num);
};

inline
policy stop() {
    return Stop();
}

inline
policy id() {
    return Id();
}

inline
policy filter(oxm::field<> f)
{
    return Filter{f};
}

inline
policy filter_not(oxm::field<>f ) {
    return Negation{Filter{f}};
}

inline
policy handler(std::function<policy(Packet&)> function)
{
    static uint64_t id_gen = 0;
    return PacketFunction{id_gen++, function};
}

inline
policy idle_timeout(duration time) {
    return FlowSettings{.idle_timeout = time};
}

inline
policy hard_timeout(duration time) {
    return FlowSettings{time, time};
}

inline
policy operator>>(const policy& lhs, const policy& rhs)
{
    return Sequential{lhs, rhs};
}

inline policy& operator>>=(policy& lhs, const policy& rhs)
{ return lhs = lhs >> rhs; }


policy operator+(policy lhs, policy rhs);

inline policy& operator+=(policy& lhs, const policy& rhs)
{ return lhs = lhs + rhs; }

inline
policy operator not(const policy& pol) {
    return Negation{pol};
}

// This is only for purpose that seq operator must have higher priorty that parallel operator
inline
policy operator|(const policy& lhs, const policy& rhs)
{
    return operator+(lhs, rhs);
}
inline policy& operator|=(policy& lhs, const policy& rhs)
{ return lhs = lhs | rhs; }

// Operators
bool operator==(const Stop&, const Stop&);
bool operator==(const Id&, const Id&);
bool operator==(const Filter& lhs, const Filter& rhs);
bool operator==(const Negation& lhs, const Negation& rhs);
bool operator==(const Modify& lhs, const Modify& rhs);
bool operator==(const PacketFunction& lhs, const PacketFunction& rhs);
bool operator==(const Sequential& lhs, const Sequential& rhs);
bool operator==(const Parallel& lhs, const Parallel& rhs);
bool operator==(const FlowSettings& lhs, const FlowSettings& rhs);

std::ostream& operator<<(std::ostream& out, const Filter& fil);
std::ostream& operator<<(std::ostream& out, const Negation& neg);
std::ostream& operator<<(std::ostream& out, const Stop& stop);
std::ostream& operator<<(std::ostream& out, const Id&);
std::ostream& operator<<(std::ostream& out, const Modify& mod);
std::ostream& operator<<(std::ostream& out, const Sequential& seq);
std::ostream& operator<<(std::ostream& out, const Parallel& par);
std::ostream& operator<<(std::ostream& out, const PacketFunction& func);
std::ostream& operator<<(std::ostream& out, const FlowSettings& flow);
} // namespace retic
} // namespace runos
