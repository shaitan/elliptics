#include <thread>
#include <utility>

#include <blackhole/attribute.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "elliptics.grpc.fb.h"

#include "../library/elliptics.h"
#include "../library/logger.hpp"

namespace grpc {

class CallData {
public:
	CallData(dnet_node *node, Elliptics::AsyncService *service, ServerCompletionQueue *cq)
		: node_(node)
		, service_(service)
		, cq_(cq)
		, responder_(&ctx_)
		, status_(CREATE) {
		proceed();
	}

	void proceed() {
		switch (status_) {
		case CREATE: {
		        DNET_LOG_INFO(node_, "GRPC: create rpc: {:p}", (void*)this);
			status_ = PROCESS;
			service_->RequestLookup(&ctx_, &request_, &responder_, cq_, cq_, this);
			break;
		}
		case PROCESS: {
			new CallData(node_, service_, cq_);

			DNET_LOG_INFO(node_, "GRPC: process rpc: {:p}, peer: {}, message: {}", (void*)this, ctx_.peer(),
                                      request_.GetRoot()->key()->str());

			std::stringstream ss;
                        const auto metadata = ctx_.client_metadata();
                        for (const auto &pair: metadata) {
                                ss << "\t" << pair.first << " = " << pair.second << std::endl;
                        }
			DNET_LOG_INFO(node_, "GRPC: process rpc: {:p}, metadata:\n{}", (void*)this, ss.str());

			auto msg_offset = mb_.CreateString("Data for " + request_.GetRoot()->key()->str());
			auto lookup_offset = CreateLookupResponse(mb_, msg_offset);
			mb_.Finish(lookup_offset);

			status_ = FINISH;
			responder_.Finish(mb_.ReleaseMessage<LookupResponse>(), Status::OK, this);
			break;
		}
		case FINISH: {
		        DNET_LOG_INFO(node_, "GRPC: finish rpc: {:p}", (void*)this);
			delete this;
			break;
		}
		}
	}

private:
	dnet_node *node_;
	Elliptics::AsyncService *service_;
	ServerCompletionQueue *cq_;
	ServerContext ctx_;

	flatbuffers::grpc::Message<LookupRequest> request_;
	flatbuffers::grpc::MessageBuilder mb_;

	ServerAsyncResponseWriter<flatbuffers::grpc::Message<LookupResponse>> responder_;

	enum CallStatus { CREATE, PROCESS, FINISH };
	CallStatus status_;
};

} // namespace grpc

struct dnet_grpc_server {
public:
	dnet_grpc_server(dnet_node *node)
	: node_(node) {
	}

	~dnet_grpc_server() {
		server_->Shutdown();

		cq_->Shutdown();

		thread_->join();
	}

	void run() {
		std::string server_address("0.0.0.0:2025");

		grpc::ServerBuilder builder;
		builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
		builder.RegisterService(&service_);

		cq_ = builder.AddCompletionQueue();

		server_ = builder.BuildAndStart();

		DNET_LOG_INFO(node_, "GRPC: server listening on {}", server_address);

		thread_.reset(new std::thread([&] {
			new grpc::CallData(node_, &service_, cq_.get());
			void *tag;
			bool ok;
			while (cq_->Next(&tag, &ok) && ok) {
				static_cast<grpc::CallData*>(tag)->proceed();
			}
		}));
	}

private:
	dnet_node *node_;
	std::unique_ptr<grpc::ServerCompletionQueue> cq_;
	Elliptics::AsyncService service_;
	std::unique_ptr<grpc::Server> server_;
	std::unique_ptr<std::thread> thread_;
};

void dnet_start_grpc_server(struct dnet_node *n) {
	n->io->grpc = new dnet_grpc_server(n);
	n->io->grpc->run();
}

void dnet_stop_grpc_server(struct dnet_node *n) {
	delete std::exchange(n->io->grpc, nullptr);
}

