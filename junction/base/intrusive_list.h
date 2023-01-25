// intrusive_list.h - intrusive list support
//
// Uses Boost; similar to folly.

#pragma once

#include <boost/intrusive/list.hpp>

namespace junction {

#ifndef DEBUG
using IntrusiveListNode = boost::intrusive::list_member_hook<
    boost::intrusive::link_mode<boost::intrusive::normal_link>>;
#else   // DEBUG
using IntrusiveListNode = boost::intrusive::list_member_hook<
    boost::intrusive::link_mode<boost::intrusive::safe_unlink>>;
#endif  // DEBUG

template <typename T, IntrusiveListNode T::*PtrToMember>
using IntrusiveList = boost::intrusive::list<
    T, boost::intrusive::member_hook<T, IntrusiveListNode, PtrToMember>,
    boost::intrusive::constant_time_size<false>>;

// Example:
//
// class Foo {
//   // Must be accessible (e.g., public or through a friend).
//   IntrusiveListNode node_;
// }
//
// IntrusiveList<Foo, &Foo::node_> head;
// head.push_back(foo_instance);

}  // namespace junction