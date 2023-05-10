package azblob

import (
	"context"
	"strings"

	"github.com/rubrikinc/azure-pipeline-go/pipeline"
)

// RequestInstrumentor defines the interface to instrument a request
type RequestInstrumentor interface {
	// TODO: Instrument more kinds of operations
	PutBlock(contentLength int64)
	PutBlockList()
	ListBlobs()
	GetBlob()
}

// NewRequestInstrumentPolicyFactory creates a factory that can create
// instrumentation policy objects which track statistics on requests eg
// bytes written & read by method type, request counts, etc
func NewRequestInstrumentPolicyFactory(instrumentor RequestInstrumentor) pipeline.Factory {
	return pipeline.FactoryFunc(func(next pipeline.Policy, po *pipeline.PolicyOptions) pipeline.PolicyFunc {
		return func(ctx context.Context, request pipeline.Request) (pipeline.Response, error) {
			resp, err := next.Do(ctx, request)

			if instrumentor != nil {
				if err == nil {
					// Do some inexpensive custom parsing to figure out the request type.
					// Note: Parsing the raw query into JSON may be too expensive to
					// allow this instrumentation to be always on.
					// We can't store the raw query as it could include high cardinality
					// fields like blockid.
					isPut := request.Method == "PUT"
					isGet := request.Method == "GET"

					// fields like blockid
					if isPut {
						// https://learn.microsoft.com/en-us/rest/api/storageservices/put-block?tabs=azure-ad
						// https://.../mycontainer/myblob?comp=block&blockid=id
						isBlock := strings.Contains(request.URL.RawQuery, "blockid")
						if isBlock {
							instrumentor.PutBlock(request.ContentLength)
						} else {
							isBlockList := strings.Contains(request.URL.RawQuery, "blocklist")
							if isBlockList {
								instrumentor.PutBlockList()
							}
						}
					} else if isGet {
						// https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs?tabs=azure-ad
						hasRestype := strings.Contains(request.URL.RawQuery, "restype")
						hasContainer := strings.Contains(request.URL.RawQuery, "container")
						hasComp := strings.Contains(request.URL.RawQuery, "comp")
						hasList := strings.Contains(request.URL.RawQuery, "list")

						// https://.../mycontainer?restype=container&comp=list
						isListBlobs := hasRestype && hasContainer && hasComp && hasList

						// https://.../mycontainer/myblob
						isGetBlob := !hasRestype && !hasComp
						if isListBlobs {
							instrumentor.ListBlobs()
						} else if isGetBlob {
							instrumentor.GetBlob()
						}
					}
				}
			}
			return resp, err
		}
	})
}
