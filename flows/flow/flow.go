package flow

import (
	"encoding/json"
	"fmt"

	"github.com/nyaruka/goflow/flows"
)

type flow struct {
	name     string
	language flows.Language
	uuid     flows.FlowUUID

	translations flows.FlowTranslations

	nodes []flows.Node

	nodeMap map[flows.NodeUUID]flows.Node
}

func (f *flow) Name() string                           { return f.name }
func (f *flow) Language() flows.Language               { return f.language }
func (f *flow) UUID() flows.FlowUUID                   { return f.uuid }
func (f *flow) Nodes() []flows.Node                    { return f.nodes }
func (f *flow) Translations() flows.FlowTranslations   { return f.translations }
func (f *flow) GetNode(uuid flows.NodeUUID) flows.Node { return f.nodeMap[uuid] }

func (f *flow) CreateRun(env flows.FlowEnvironment, contact flows.Contact, parent flows.FlowRun) flows.FlowRun {
	return newRun(env, f, contact, parent)
}

// Validates that structurally we are sane. IE, all required fields are present and
// all exits with destinations point to valid endpoints.
func (f *flow) Validate() error {
	var err error
	f.nodeMap = make(map[flows.NodeUUID]flows.Node)

	// build up a list of all our node ids
	for i, node := range f.nodes {
		// make sure we haven't seen this node before
		if f.nodeMap[node.UUID()] != nil {
			return fmt.Errorf("Duplicate node uuid: '%s'", node.UUID())
		}
		f.nodeMap[node.UUID()] = f.nodes[i]
	}

	for _, node := range f.nodes {
		// validate all our actions
		for _, action := range node.Actions() {
			err = action.Validate()
			if err != nil {
				asJSON, jerr := json.MarshalIndent(action, "", "  ")
				if jerr != nil {
					return fmt.Errorf("%+v: %v", action, err)
				}
				return fmt.Errorf("%s: %v", asJSON, err)
			}
		}

		// and our router if we have one
		router := node.Router()
		if router != nil {
			err = router.Validate(node.Exits())
			if err != nil {
				asJSON, jerr := json.MarshalIndent(node.Router(), "", "  ")
				if jerr != nil {
					return fmt.Errorf("%+v: %v", node.Router(), err)
				}
				return fmt.Errorf("%s: %v", asJSON, err)
			}
		}

		// make sure all our exits have valid destinations
		for _, exit := range node.Exits() {
			if exit.Destination() != "" && f.nodeMap[exit.Destination()] == nil {
				return fmt.Errorf("Invalid destination node uuid:'%s'", exit.Destination())
			}
		}
	}
	return err
}

//------------------------------------------------------------------------------------------
// JSON Encoding / Decoding
//------------------------------------------------------------------------------------------

// ReadFlow reads a single flow definition from the passed in byte array
func ReadFlow(data json.RawMessage) (flows.Flow, error) {
	flow := &flow{}
	err := json.Unmarshal(data, flow)
	if err == nil {
		err = flow.Validate()
	}
	return flow, err
}

// ReadFlows reads a slice of flow definitions from the passed in byte array
func ReadFlows(data json.RawMessage) ([]flows.Flow, error) {
	var container []*flow
	err := json.Unmarshal(data, &container)
	if err != nil {
		return nil, err
	}

	flows := make([]flows.Flow, len(container))
	for i := range container {
		flows[i] = container[i]
		flows[i].Validate()
	}

	return flows, err
}

type flowEnvelope struct {
	Name         string           `json:"name"`
	Language     flows.Language   `json:"language"`
	UUID         flows.FlowUUID   `json:"uuid"`
	Localization flowTranslations `json:"localization"`
	Nodes        []*node          `json:"nodes"`

	// only for writing out, optional
	Metadata map[string]interface{} `json:"_ui,omitempty"`
}

func (f *flow) UnmarshalJSON(data []byte) error {
	var envelope flowEnvelope
	var err error

	err = json.Unmarshal(data, &envelope)
	if err != nil {
		return err
	}

	f.name = envelope.Name
	f.language = envelope.Language
	f.uuid = envelope.UUID

	f.translations = &envelope.Localization

	// for each node
	f.nodes = make([]flows.Node, len(envelope.Nodes))
	for i := range envelope.Nodes {
		f.nodes[i] = envelope.Nodes[i]
	}

	return err
}

func (f *flow) MarshalJSON() ([]byte, error) {

	var fe = flowEnvelope{}
	fe.Name = f.name
	fe.Language = f.language
	fe.UUID = f.uuid

	if f.translations != nil {
		fe.Localization = *f.translations.(*flowTranslations)
	}

	fe.Nodes = make([]*node, len(f.nodes))
	for i := range f.nodes {
		fe.Nodes[i] = f.nodes[i].(*node)
	}

	return json.Marshal(&fe)
}