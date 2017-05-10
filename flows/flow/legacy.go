package flow

import (
	"encoding/json"
	"fmt"

	"github.com/nyaruka/goflow/excellent"
	"github.com/nyaruka/goflow/flows"

	"github.com/nyaruka/goflow/flows/actions"
	"github.com/nyaruka/goflow/flows/routers"
	"github.com/nyaruka/goflow/utils"
	"github.com/satori/go.uuid"
)

type legacyFlow struct {
	flow
	envelope legacyFlowEnvelope
}

type legacyFlowEnvelope struct {
	BaseLanguage flows.Language         `json:"base_language"`
	Metadata     legacyMetadataEnvelope `json:"metadata"`
	RuleSets     []legacyRuleSet        `json:"rule_sets"`
	ActionSets   []legacyActionSet      `json:"action_sets"`
}

type legacyMetadataEnvelope struct {
	UUID flows.FlowUUID `json:"uuid"`
	Name string         `json:"name"`
}

type legacyRule struct {
	Destination flows.NodeUUID            `json:"destination"`
	Test        utils.TypedEnvelope       `json:"test"`
	Category    map[flows.Language]string `json:"category"`
	ExitType    string                    `json:"exit_type"`
}

type legacyRuleSet struct {
	Y       int            `json:"y"`
	X       int            `json:"x"`
	UUID    flows.NodeUUID `json:"uuid"`
	Type    string         `json:"ruleset_type"`
	Label   string         `json:"label"`
	Operand string         `json:"operand"`
	Rules   []legacyRule   `json:"rules"`
}

type legacyActionSet struct {
	Y           int            `json:"y"`
	X           int            `json:"x"`
	Destination flows.NodeUUID `json:"destination"`
	UUID        flows.NodeUUID `json:"uuid"`
	Actions     []legacyAction `json:"actions"`
}

type legacyGroup struct {
	Name string          `json:"name"`
	UUID flows.GroupUUID `json:"uuid"`
}

type legacyAction struct {
	Type string           `json:"type"`
	UUID flows.ActionUUID `json:"uuid"`
	Name string           `json:"name"`

	// message actions
	Msg map[flows.Language]string `json:"msg"`

	// group actions
	Groups []legacyGroup `json:"groups"`

	// save actions
	Field string `json:"field"`
	Value string `json:"value"`
	Label string `json:"label"`

	// set language
	Language flows.Language `json:"lang"`

	// webhook
	Action  string `json:"action"`
	Webhook string `json:"webhook"`
}

type subflowTest struct {
	ExitType string `json:"exit_type"`
}

type webhookTest struct {
	Status string `json:"status"`
}

type localizedStringTest struct {
	Test map[flows.Language]string `json:"test"`
}

type stringTest struct {
	Test string `jons:"test"`
}

type localizations map[flows.Language]flows.Action

// readLegacyFlows reads in legacy formatted flows
func readLegacyFlows(data json.RawMessage) ([]legacyFlow, error) {
	var flows []legacyFlow
	err := json.Unmarshal(data, &flows)
	fmt.Println(err)
	return flows, err
}

type translationMap map[flows.Language]string

func addTranslationMap(translations *flowTranslations, mapped translationMap, uuid flows.UUID, key string) {
	for language, translation := range mapped {
		items := itemTranslations{}
		expression, _ := excellent.TranslateTemplate(translation)
		items[key] = expression
		addTranslation(translations, language, uuid, items)
	}
}

func addTranslation(translations *flowTranslations, lang flows.Language, uuid flows.UUID, items itemTranslations) {
	langTranslations, ok := (*translations)[lang]
	if !ok {
		langTranslations = &languageTranslations{}
	}

	(*langTranslations)[uuid] = items
	(*translations)[lang] = langTranslations
}

func createAction(lang flows.Language, a legacyAction, fieldMap map[string]flows.FieldUUID, translations *flowTranslations) flows.Action {

	if a.UUID == "" {
		a.UUID = flows.ActionUUID(uuid.NewV4().String())
	}

	switch a.Type {
	case "flow":
		return &actions.FlowAction{}
	case "reply":
		addTranslationMap(translations, a.Msg, flows.UUID(a.UUID), "text")
		expression, _ := excellent.TranslateTemplate(a.Msg[lang])
		return &actions.MsgAction{
			Text: expression,
			BaseAction: actions.BaseAction{
				Uuid: a.UUID,
			},
		}
	case "add_group":
		// TODO: list of groups per action?
		group := a.Groups[0]
		return &actions.AddToGroupAction{
			Group: group.UUID,
			Name:  group.Name,
			BaseAction: actions.BaseAction{
				Uuid: a.UUID,
			},
		}
	case "del_group":
		// TODO: remove from group action
		group := a.Groups[0]
		return &actions.AddToGroupAction{
			Group: group.UUID,
			Name:  group.Name,
			BaseAction: actions.BaseAction{
				Uuid: a.UUID,
			},
		}
	case "save":
		fieldUUID, ok := fieldMap[a.Value]
		if !ok {
			fieldUUID = flows.FieldUUID(uuid.NewV4().String())
			fieldMap[a.Value] = fieldUUID
		}

		translated, _ := excellent.TranslateTemplate(a.Value)

		return &actions.SaveToContactAction{
			Name:  a.Label,
			Value: translated,
			Field: fieldUUID,
			BaseAction: actions.BaseAction{
				Uuid: a.UUID,
			},
		}
	case "set_language":
		return &actions.SetLanguageAction{
			Language: a.Language,
			BaseAction: actions.BaseAction{
				Uuid: a.UUID,
			},
		}
	case "api":
		translated, _ := excellent.TranslateTemplate(a.Webhook)
		return &actions.WebhookAction{
			Method: a.Action,
			URL:    translated,
			BaseAction: actions.BaseAction{
				Uuid: a.UUID,
			},
		}
	default:
		fmt.Printf("Couldn't create action for %s\n", a.Type)
		return nil
	}
}

func createCase(lang flows.Language, exitMap map[string]flows.Exit, r legacyRule, translations *flowTranslations) (routers.Case, error) {
	category := r.Category[lang]
	testType := r.Test.Type
	var arguments []string
	var err error

	caseUUID := flows.UUID(uuid.NewV4().String())

	switch r.Test.Type {
	case "subflow":
		testType = "has_any_word"
		test := subflowTest{}
		err = json.Unmarshal(r.Test.Data, &test)
		if test.ExitType == "completed" {
			arguments = []string{"C"}
		} else {
			arguments = []string{"E"}
		}
	case "webhook_status":
		test := webhookTest{}
		err = json.Unmarshal(r.Test.Data, &test)
		if test.Status == "success" {
			testType = "is_webhook_success"
		} else {
			return routers.Case{}, fmt.Errorf("No failure test")
		}
	case "eq":
		test := stringTest{}
		err = json.Unmarshal(r.Test.Data, &test)
		arguments = []string{test.Test}

	case "regex":
		fallthrough
	case "contains_any":
		test := localizedStringTest{}
		err = json.Unmarshal(r.Test.Data, &test)

		// TODO: arguments should be an array
		addTranslationMap(translations, test.Test, caseUUID, "arguments")
		arguments = []string{test.Test[lang]}
	}

	return routers.Case{
		UUID:      caseUUID,
		Type:      testType,
		Exit:      exitMap[category].UUID(),
		Arguments: arguments,
	}, err
}

type categoryName struct {
	destination  flows.NodeUUID
	translations translationMap
	order        int
}

func parseRules(lang flows.Language, r legacyRuleSet, translations *flowTranslations) ([]flows.Exit, []routers.Case, flows.ExitUUID) {

	// find our discrete categories
	categoryMap := make(map[string]categoryName)
	order := 0
	for i := range r.Rules {
		category := r.Rules[i].Category[lang]
		_, ok := categoryMap[category]
		if !ok {
			categoryMap[category] = categoryName{
				destination:  r.Rules[i].Destination,
				translations: r.Rules[i].Category,
				order:        order,
			}
			order++
		}
	}

	// create exists for each category
	exits := make([]flows.Exit, len(categoryMap))
	exitMap := make(map[string]flows.Exit)
	for k, category := range categoryMap {
		uuid := flows.ExitUUID(uuid.NewV4().String())

		addTranslationMap(translations, category.translations, flows.UUID(uuid), "label")

		exits[category.order] = &exit{
			name:        k,
			uuid:        uuid,
			destination: category.destination,
		}
		exitMap[k] = exits[category.order]
	}

	var defaultExit flows.ExitUUID

	// create any cases to map to our new exits
	var cases []routers.Case
	for i := range r.Rules {
		if r.Rules[i].Test.Type != "true" {

			c, err := createCase(lang, exitMap, r.Rules[i], translations)
			if err == nil {
				cases = append(cases, c)
			} else if r.Rules[i].Test.Type == "webhook_status" {
				// webhook failures don't have a case, instead they are the default
				defaultExit = exitMap[r.Rules[i].Category[lang]].UUID()
			}
		} else {
			defaultExit = exitMap[r.Rules[i].Category[lang]].UUID()
		}
	}

	return exits, cases, defaultExit
}

func createRuleNode(lang flows.Language, r legacyRuleSet, translations *flowTranslations) *node {
	node := &node{}
	node.uuid = r.UUID

	exits, cases, defaultExit := parseRules(lang, r, translations)

	switch r.Type {
	case "subflow":
		// subflow rulesets operate on the child flow status
		node.router = &routers.SwitchRouter{
			Default: defaultExit,
			Operand: "@child.status",
			Cases:   cases,
		}

	case "webhook":
		// subflow rulesets operate on the child flow status
		node.router = &routers.SwitchRouter{
			Default: defaultExit,
			Operand: "@webhook",
			Cases:   cases,
		}
	case "flow_field":
		fallthrough
	case "form_field":
		fallthrough
	case "group":
		fallthrough
	case "contact_field":
		fallthrough
	case "wait_message":
		fallthrough
	case "expression":
		operand, _ := excellent.TranslateTemplate(r.Operand)
		node.router = &routers.SwitchRouter{
			Default: defaultExit,
			Operand: operand,
			Cases:   cases,
			BaseRouter: routers.BaseRouter{
				Name_: r.Label,
			},
		}
	case "random":
		node.router = &routers.RandomRouter{}
	default:
		fmt.Printf("No router for %s\n", r.Type)
	}

	node.exits = exits

	return node
}

func createActionNode(lang flows.Language, a legacyActionSet, fieldMap map[string]flows.FieldUUID, translations *flowTranslations) *node {
	node := &node{}

	node.uuid = a.UUID
	node.actions = make([]flows.Action, len(a.Actions))
	for i := range a.Actions {
		action := createAction(lang, a.Actions[i], fieldMap, translations)
		node.actions[i] = action
	}

	node.exits = make([]flows.Exit, 1)
	node.exits[0] = &exit{
		destination: a.Destination,
		uuid:        flows.ExitUUID(uuid.NewV4().String()),
	}
	return node

}

func (f *legacyFlow) UnmarshalJSON(data []byte) error {
	var envelope legacyFlowEnvelope
	var err error

	err = json.Unmarshal(data, &envelope)
	if err != nil {
		return err
	}

	fieldMap := make(map[string]flows.FieldUUID)

	f.language = envelope.BaseLanguage
	f.name = envelope.Metadata.Name
	f.uuid = envelope.Metadata.UUID

	translations := &flowTranslations{}

	f.nodes = make([]flows.Node, len(envelope.ActionSets)+len(envelope.RuleSets))
	for i := range envelope.ActionSets {
		node := createActionNode(f.language, envelope.ActionSets[i], fieldMap, translations)
		f.nodes[i] = node
	}

	for i := range envelope.RuleSets {
		f.nodes[len(envelope.ActionSets)+i] = createRuleNode(f.language, envelope.RuleSets[i], translations)
	}

	f.translations = translations
	f.envelope = envelope

	//for i := range f.nodes {
	//	fmt.Println("Node:", f.nodes[i])
	//}

	return err
}

func (f *legacyFlow) MarshalJSON() ([]byte, error) {

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

	// add in our ui metadata
	fe.Metadata = make(map[string]interface{})
	fe.Metadata["nodes"] = make(map[flows.NodeUUID]interface{})
	nodes := fe.Metadata["nodes"].(map[flows.NodeUUID]interface{})

	for i := range f.envelope.ActionSets {
		actionset := f.envelope.ActionSets[i]
		nmd := make(map[string]interface{})
		nmd["position"] = map[string]int{
			"x": actionset.X,
			"y": actionset.Y,
		}
		nodes[actionset.UUID] = nmd
	}

	for i := range f.envelope.RuleSets {
		ruleset := f.envelope.RuleSets[i]
		nmd := make(map[string]interface{})
		nmd["position"] = map[string]int{
			"x": ruleset.X,
			"y": ruleset.Y,
		}
		nodes[ruleset.UUID] = nmd
	}

	return json.Marshal(&fe)
}