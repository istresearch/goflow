package test

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/nyaruka/goflow/assets"
	"github.com/nyaruka/goflow/assets/static"
	_ "github.com/nyaruka/goflow/extensions/transferto"
	"github.com/nyaruka/goflow/flows"
	"github.com/nyaruka/goflow/flows/engine"
	"github.com/nyaruka/goflow/flows/resumes"
	"github.com/nyaruka/goflow/flows/triggers"
	"github.com/nyaruka/goflow/legacy"
	"github.com/nyaruka/goflow/utils"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var flowTests = []struct {
	assets string
	output string
}{
	{"airtime.json", "airtime.test_disabled.json"},
	{"all_actions.json", "all_actions.test.json"},
	{"brochure.json", "brochure.test.json"},
	{"date_parse.json", "date_parse.test.json"},
	{"default_result.json", "default_result.test.json"},
	{"dynamic_groups_correction.json", "dynamic_groups_correction.test.json"},
	{"dynamic_groups.json", "dynamic_groups.test.json"},
	{"empty.json", "empty.test.json"},
	{"enter_flow_loop.json", "enter_flow_loop.test.json"},
	{"enter_flow_terminal.json", "enter_flow_terminal.test.json"},
	{"initial_wait.json", "initial_wait.test.json"},
	{"legacy_extra.json", "legacy_extra.test.json"},
	{"no_contact.json", "no_contact.test.json"},
	{"node_loop.json", "node_loop.test.json"},
	{"redact_urns.json", "redact_urns.test.json"},
	{"resthook.json", "resthook.test.json"},
	{"router_tests.json", "router_tests.test.json"},
	{"subflow_loop_with_wait.json", "subflow_loop_with_wait.test.json"},
	{"subflow_other.json", "subflow_other.test.json"},
	{"subflow.json", "subflow.test_resume_with_expiration.json"},
	{"subflow.json", "subflow.test.json"},
	{"triggered.json", "triggered.test.json"},
	{"two_questions_offline.json", "two_questions_offline.test.json"},
	{"two_questions.json", "two_questions.test_resume_with_expiration.json"},
	{"two_questions.json", "two_questions.test.json"},
	{"webhook_migrated.json", "webhook_migrated.test.json"},
	{"webhook_persists.json", "webhook_persists.test.json"},
	{"legacy/favorites.json", "legacy/favorites.test.json"},
}

var writeOutput bool
var serverURL = ""

func init() {
	flag.BoolVar(&writeOutput, "write", false, "whether to rewrite test output")
}

func marshalEventLog(eventLog []flows.Event) ([]json.RawMessage, error) {
	marshaled := make([]json.RawMessage, len(eventLog))
	var err error

	for i := range eventLog {
		marshaled[i], err = utils.JSONMarshal(eventLog[i])
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling event")
		}
	}
	return marshaled, nil
}

type Output struct {
	Session json.RawMessage   `json:"session"`
	Events  []json.RawMessage `json:"events"`
}

type FlowTest struct {
	Trigger json.RawMessage   `json:"trigger"`
	Resumes []json.RawMessage `json:"resumes"`
	Outputs []json.RawMessage `json:"outputs"`
}

type runResult struct {
	session flows.Session
	outputs []*Output
}

type legacyAssets struct {
	LegacyFlows []json.RawMessage      `json:"legacy_flows"`
	OtherAssets map[string]interface{} `json:"other_assets"`
}

// loads assets from a file in one of two formats, indicated in the path:
//   1. ./*.json a regular static assets file
//   2. legacy/*.json a file with both legacy flow defs and assets, i.e. {"legacy_flows": [], "other_assets": {}}
func loadAssets(path string) (flows.SessionAssets, error) {
	// load the test specific assets
	assetsJSON, err := ioutil.ReadFile(fmt.Sprintf("testdata/flows/%s", path))
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(path, "legacy/") {
		la := &legacyAssets{}
		if err := json.Unmarshal(assetsJSON, la); err != nil {
			return nil, errors.Wrap(err, "unable to read legacy assets")
		}

		migratedFlows := make([]json.RawMessage, len(la.LegacyFlows))
		for f, legacyFlow := range la.LegacyFlows {
			migrated, err := legacy.MigrateLegacyDefinition(legacyFlow, "")
			if err != nil {
				return nil, errors.Wrap(err, "unable to migrate legacy flow")
			}
			migratedFlows[f] = migrated
		}

		la.OtherAssets["flows"] = migratedFlows
		assetsJSON, err = json.Marshal(la.OtherAssets)
		if err != nil {
			return nil, err
		}

		//ioutil.WriteFile(fmt.Sprintf("testdata/flows/%s.migrated", path), assetsJSON, 0666)
	}

	// rewrite the URL on any webhook actions
	assetsJSON = json.RawMessage(strings.Replace(string(assetsJSON), "http://localhost", serverURL, -1))

	// create the assets source
	source, err := static.NewSource(assetsJSON)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading test assets '%s'", path)
	}

	return engine.NewSessionAssets(source)
}

func runFlow(assetsPath string, rawTrigger json.RawMessage, rawResumes []json.RawMessage) (runResult, error) {
	// load the test specific assets
	sa, err := loadAssets(assetsPath)
	if err != nil {
		return runResult{}, err
	}

	trigger, err := triggers.ReadTrigger(sa, rawTrigger, assets.PanicOnMissing)
	if err != nil {
		return runResult{}, errors.Wrapf(err, "error unmarshalling trigger")
	}

	eng := engine.NewBuilder().WithDefaultUserAgent("goflow-testing").Build()
	session := eng.NewSession(sa)

	sprint, err := session.Start(trigger)
	if err != nil {
		return runResult{}, err
	}

	outputs := make([]*Output, 0)

	// try to resume the session for each of the provided resumes
	for r, rawResume := range rawResumes {
		sessionJSON, err := utils.JSONMarshalPretty(session)
		if err != nil {
			return runResult{}, errors.Wrap(err, "error marshalling output")
		}
		marshalledEvents, err := marshalEventLog(sprint.Events())
		if err != nil {
			return runResult{}, err
		}

		outputs = append(outputs, &Output{sessionJSON, marshalledEvents})

		session, err = eng.ReadSession(sa, sessionJSON, assets.PanicOnMissing)
		if err != nil {
			return runResult{}, errors.Wrap(err, "error marshalling output")
		}

		// if we aren't at a wait, that's an error
		if session.Wait() == nil {
			return runResult{}, errors.Errorf("did not stop at expected wait, have unused resumes: %#v", rawResumes[r:])
		}

		resume, err := resumes.ReadResume(sa, rawResume, assets.PanicOnMissing)
		if err != nil {
			return runResult{}, err
		}

		sprint, err = session.Resume(resume)
		if err != nil {
			return runResult{}, err
		}
	}

	sessionJSON, err := utils.JSONMarshalPretty(session)
	if err != nil {
		return runResult{}, errors.Wrap(err, "error marshalling output")
	}

	marshalledEvents, err := marshalEventLog(sprint.Events())
	if err != nil {
		return runResult{}, err
	}

	outputs = append(outputs, &Output{sessionJSON, marshalledEvents})

	return runResult{session, outputs}, nil
}

func TestFlows(t *testing.T) {
	server := NewTestHTTPServer(49999)
	defer server.Close()
	defer utils.SetUUIDGenerator(utils.DefaultUUIDGenerator)
	defer utils.SetTimeSource(utils.DefaultTimeSource)

	// save away our server URL so we can rewrite our URLs
	serverURL = server.URL

	for _, tc := range flowTests {
		utils.SetUUIDGenerator(utils.NewSeededUUID4Generator(123456))
		utils.SetTimeSource(utils.NewSequentialTimeSource(time.Date(2018, 7, 6, 12, 30, 0, 123456789, time.UTC)))

		testJSON, err := ioutil.ReadFile(fmt.Sprintf("testdata/flows/%s", tc.output))
		require.NoError(t, err, "Error reading output file for flow '%s' and output '%s': %s", tc.assets, tc.output, err)

		flowTest := &FlowTest{}
		err = json.Unmarshal(json.RawMessage(testJSON), &flowTest)
		require.NoError(t, err, "Error unmarshalling output for flow '%s' and output '%s': %s", tc.assets, tc.output, err)

		// run our flow
		runResult, err := runFlow(tc.assets, flowTest.Trigger, flowTest.Resumes)
		if err != nil {
			t.Errorf("Error running flow for flow '%s' and output '%s': %s", tc.assets, tc.output, err)
			continue
		}

		if writeOutput {
			// we are writing new outputs, we write new files but don't test anything
			rawOutputs := make([]json.RawMessage, len(runResult.outputs))
			for i := range runResult.outputs {
				rawOutputs[i], err = utils.JSONMarshal(runResult.outputs[i])
				require.NoError(t, err)
			}
			flowTest := &FlowTest{Trigger: flowTest.Trigger, Resumes: flowTest.Resumes, Outputs: rawOutputs}
			testJSON, err := utils.JSONMarshalPretty(flowTest)
			require.NoError(t, err, "Error marshalling test definition: %s", err)

			testJSON, _ = NormalizeJSON(testJSON)

			// write our output
			outputFilename := fmt.Sprintf("testdata/flows/%s", tc.output)
			err = ioutil.WriteFile(outputFilename, testJSON, 0644)
			require.NoError(t, err, "Error writing test file to %s: %s", outputFilename, err)
		} else {
			// start by checking we have the expected number of outputs
			if !assert.Equal(t, len(flowTest.Outputs), len(runResult.outputs), "wrong number of outputs for flow test %s", tc.assets) {
				continue
			}

			// then check each output
			for i, actual := range runResult.outputs {
				// unmarshal our expected outputsinto session+events
				expected := &Output{}
				err := json.Unmarshal(flowTest.Outputs[i], expected)
				require.NoError(t, err, "error unmarshalling output")

				// first the session
				if !AssertEqualJSON(t, expected.Session, actual.Session, fmt.Sprintf("session is different in output[%d] for flow test %s", i, tc.assets)) {
					break
				}

				// and then each event
				for e := range actual.Events {
					if !AssertEqualJSON(t, expected.Events[e], actual.Events[e], fmt.Sprintf("event[%d] is different in output[%d] for flow test %s", e, i, tc.assets)) {
						break
					}
				}
			}
		}
	}
}
