package docs_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/nyaruka/goflow/cmd/docgen/docs"
	"github.com/nyaruka/goflow/utils/jsonx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDocs(t *testing.T) {
	// create a temporary directory to hold generated doc files
	outputDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	// create a temporary directory to hold generated locale files
	localeDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	defer os.RemoveAll(outputDir)
	defer os.RemoveAll(localeDir)

	// and setup the locale directory for en_US and es
	os.Mkdir(path.Join(localeDir, "en_US"), 0700)
	os.Mkdir(path.Join(localeDir, "es"), 0700)

	ioutil.WriteFile(path.Join(localeDir, "en_US", "flows.po"), []byte(``), 0700)
	ioutil.WriteFile(path.Join(localeDir, "es", "flows.po"), []byte(``), 0700)

	// tests run from the same working directory as the test file, so two directories up is our goflow root
	err = docs.Generate("../../../", outputDir, localeDir)
	require.NoError(t, err)

	// check each rendered template for changes
	for _, template := range docs.Templates {
		existing, err := ioutil.ReadFile("../../../docs/en-us/md/" + template.Path)
		require.NoError(t, err)

		generated, err := ioutil.ReadFile(path.Join(outputDir, "en-us", "md", template.Path))
		require.NoError(t, err)

		// if the docs we just generated don't match the existing ones, someone needs to run docgen
		require.Equal(t, string(existing), string(generated), "changes have been made that require re-running docgen (go install github.com/nyaruka/goflow/cmd/docgen; docgen)")
	}

	// check other outputs
	completion := readJSONOutput(t, outputDir, "en-us", "completion.json").(map[string]interface{})
	assert.Contains(t, completion, "types")
	assert.Contains(t, completion, "root")

	types := completion["types"].([]interface{})
	assert.Equal(t, 13, len(types))

	root := completion["root"].([]interface{})
	assert.Equal(t, 11, len(root))

	functions := readJSONOutput(t, outputDir, "en-US", "functions.json").([]interface{})
	assert.Equal(t, 80, len(functions))
}

func readJSONOutput(t *testing.T, file ...string) interface{} {
	output, err := ioutil.ReadFile(path.Join(file...))
	require.NoError(t, err)

	generic, err := jsonx.DecodeGeneric(output)
	require.NoError(t, err)

	return generic
}
