package zendesk

import (
	"net/http"
	"strconv"

	"github.com/nyaruka/goflow/flows"
	"github.com/nyaruka/goflow/utils/httpx"
	"github.com/nyaruka/goflow/utils/uuids"
)

type service struct {
	client   *Client
	ticketer *flows.Ticketer
}

// NewService creates a new Zendesk ticketing service
func NewService(httpClient *http.Client, httpRetries *httpx.RetryConfig, ticketer *flows.Ticketer, subdomain, emailAddress, apiToken string) flows.TicketService {
	return &service{
		client:   NewClient(httpClient, httpRetries, subdomain, emailAddress, apiToken),
		ticketer: ticketer,
	}
}

// Open opens a ticket which for mailgun means just sending an initial email
func (s *service) Open(session flows.Session, subject, body string, logHTTP flows.HTTPLogCallback) (*flows.Ticket, error) {
	ticketUUID := flows.TicketUUID(uuids.New())

	ticketResponse, trace, err := s.client.CreateTicket(subject, body)
	if trace != nil {
		logHTTP(flows.NewHTTPLog(trace, flows.HTTPStatusFromCode))
	}
	if err != nil {
		return nil, err
	}

	return flows.NewTicket(ticketUUID, s.ticketer, subject, body, strconv.Itoa(ticketResponse.ID)), nil
}
