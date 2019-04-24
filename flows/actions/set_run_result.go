package actions

import (
	"github.com/nyaruka/goflow/flows"
	"github.com/nyaruka/goflow/flows/events"
	"github.com/nyaruka/goflow/utils"
)

func init() {
	RegisterType(TypeSetRunResult, func() flows.Action { return &SetRunResultAction{} })
}

// TypeSetRunResult is the type for the set run result action
const TypeSetRunResult string = "set_run_result"

// SetRunResultAction can be used to save a result for a flow. The result will be available in the context
// for the run as @results.[name]. The optional category can be used as a way of categorizing results,
// this can be useful for reporting or analytics.
//
// Both the value and category fields may be templates. A [event:run_result_changed] event will be created with the
// final values.
//
//   {
//     "uuid": "8eebd020-1af5-431c-b943-aa670fc74da9",
//     "type": "set_run_result",
//     "name": "Gender",
//     "value": "m",
//     "category": "Male"
//   }
//
// @action set_run_result
type SetRunResultAction struct {
	BaseAction
	universalAction

	Name     string `json:"name" validate:"required"`
	Value    string `json:"value"`
	Category string `json:"category,omitempty"`
}

// NewSetRunResultAction creates a new set run result action
func NewSetRunResultAction(uuid flows.ActionUUID, name string, value string, category string) *SetRunResultAction {
	return &SetRunResultAction{
		BaseAction: NewBaseAction(TypeSetRunResult, uuid),
		Name:       name,
		Value:      value,
		Category:   category,
	}
}

// Execute runs this action
func (a *SetRunResultAction) Execute(run flows.FlowRun, step flows.Step, logModifier flows.ModifierCallback, logEvent flows.EventCallback) error {
	// get our evaluated value
	value, err := run.EvaluateTemplate(a.Value)

	// log any error received
	if err != nil {
		logEvent(events.NewErrorEvent(err))
		return nil
	}

	categoryLocalized := run.GetText(utils.UUID(a.UUID()), "category", a.Category)
	if a.Category == categoryLocalized {
		categoryLocalized = ""
	}

	a.saveResult(run, step, a.Name, value, a.Category, categoryLocalized, "", nil, logEvent)
	return nil
}

// Inspect inspects this object and any children
func (a *SetRunResultAction) Inspect(inspect func(flows.Inspectable)) {
	inspect(a)
}

// EnumerateTemplates enumerates all expressions on this object and its children
func (a *SetRunResultAction) EnumerateTemplates(include flows.TemplateIncluder) {
	include.String(&a.Value)
}

// EnumerateResults enumerates all potential results on this object
func (a *SetRunResultAction) EnumerateResults(include func(*flows.ResultSpec)) {
	if a.Category != "" {
		include(flows.NewResultSpec(a.Name, []string{a.Category}))
	} else {
		include(flows.NewResultSpec(a.Name, nil))
	}
}
