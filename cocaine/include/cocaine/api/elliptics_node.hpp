#ifndef COCAINE_API_ELLIPTICS_NODE
#define COCAINE_API_ELLIPTICS_NODE

#include <cocaine/repository.hpp>

namespace cocaine { namespace api {

struct elliptics_node_t;

/**
 * Traits for local elliptics node component.
 * Factory is statefull and always returns the same assigned in node, assigned in ctor
 */
template<>
struct category_traits<elliptics_node_t> {
	typedef dnet_node* ptr_type;

	struct factory_type: public basic_factory<elliptics_node_t> {
		virtual ptr_type get() = 0;
	};

	template<class T>
	struct default_factory: public factory_type {
		default_factory(dnet_node* _n)
		: n(_n) { }

		virtual dnet_node* get() {
			return n;
		}
	private:
		dnet_node *n;
	};
};


// This one is only component category tag.
// Real type of the elliptics_node_t component is dnet_node*
struct elliptics_node_t {
	typedef elliptics_node_t category_type;
	typedef category_traits<elliptics_node_t>::default_factory<elliptics_node_t> factory_t;
};

} // namespace api
} // namespace cocaine

#endif
