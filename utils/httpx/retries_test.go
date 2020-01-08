package httpx_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nyaruka/goflow/utils/dates"
	"github.com/nyaruka/goflow/utils/httpx"
	"github.com/nyaruka/goflow/utils/random"

	"github.com/stretchr/testify/assert"
)

func TestNewExponentialRetries(t *testing.T) {
	defer random.SetGenerator(random.DefaultGenerator)

	retries := httpx.NewExponentialRetries(5*time.Second, 2, 0.5)

	assert.Equal(t, []time.Duration{5 * time.Second, 10 * time.Second}, retries.Backoffs)
	assert.Equal(t, float64(0.5), retries.Jitter)

	retries = httpx.NewExponentialRetries(2*time.Second, 4, 0.0)

	assert.Equal(t, []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}, retries.Backoffs)
	assert.Equal(t, float64(0.0), retries.Jitter)
	assert.Equal(t, 4, retries.MaxRetries())

	random.SetGenerator(random.NewSeededGenerator(123456))

	// test backoffs with no jitter
	assert.Equal(t, 2*time.Second, retries.Backoff(0))
	assert.Equal(t, 4*time.Second, retries.Backoff(1))
	assert.Equal(t, 8*time.Second, retries.Backoff(2))
	assert.Equal(t, 16*time.Second, retries.Backoff(3))
	assert.Panics(t, func() { retries.Backoff(4) })

	// test backoffs with 5% jitter
	retries.Jitter = 0.05

	assert.Equal(t, time.Duration(1964211898), retries.Backoff(0))
	assert.Equal(t, time.Duration(3970345144), retries.Backoff(1))
	assert.Equal(t, time.Duration(8142741864), retries.Backoff(2))
	assert.Equal(t, time.Duration(15884061444), retries.Backoff(3))

	// test backoffs with 100% jitter
	retries.Jitter = 1.0

	assert.Equal(t, time.Duration(1280781995), retries.Backoff(0))
	assert.Equal(t, time.Duration(5877181643), retries.Backoff(1))
	assert.Equal(t, time.Duration(8587700930), retries.Backoff(2))
	assert.Equal(t, time.Duration(9120513163), retries.Backoff(3))
}

func TestDoWithRetries(t *testing.T) {
	defer httpx.SetRequestor(httpx.DefaultRequestor)

	mocks := httpx.NewMockRequestor(map[string][]httpx.MockResponse{
		"http://temba.io/1/": []httpx.MockResponse{
			httpx.NewMockResponse(502, "a", nil),
		},
		"http://temba.io/2/": []httpx.MockResponse{
			httpx.NewMockResponse(503, "a", nil),
			httpx.NewMockResponse(504, "b", nil),
			httpx.NewMockResponse(505, "c", nil),
		},
		"http://temba.io/3/": []httpx.MockResponse{
			httpx.NewMockResponse(200, "a", nil),
		},
		"http://temba.io/4/": []httpx.MockResponse{
			httpx.NewMockResponse(502, "a", nil),
		},
		"http://temba.io/5/": []httpx.MockResponse{
			httpx.NewMockResponse(502, "a", nil),
			httpx.NewMockResponse(200, "b", nil),
		},
		"http://temba.io/6/": []httpx.MockResponse{
			httpx.NewMockResponse(429, "a", map[string]string{"Retry-After": "1"}),
			httpx.NewMockResponse(201, "b", nil),
		},
		"http://temba.io/7/": []httpx.MockResponse{
			httpx.NewMockResponse(429, "a", map[string]string{"Retry-After": "100"}),
		},
	})
	httpx.SetRequestor(mocks)

	// no retry config
	trace, err := httpx.DoTrace(http.DefaultClient, "GET", "http://temba.io/1/", nil, nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, 502, trace.Response.StatusCode)

	// a retry config which can make 3 attempts
	retries := httpx.NewFixedRetries(1*time.Millisecond, 2*time.Millisecond)

	// retrying thats ends with failure
	trace, err = httpx.DoTrace(http.DefaultClient, "GET", "http://temba.io/2/", nil, nil, retries)
	assert.NoError(t, err)
	assert.Equal(t, 505, trace.Response.StatusCode)

	// retrying not needed
	trace, err = httpx.DoTrace(http.DefaultClient, "GET", "http://temba.io/3/", nil, nil, retries)
	assert.NoError(t, err)
	assert.Equal(t, 200, trace.Response.StatusCode)

	// retrying not used for POSTs
	trace, err = httpx.DoTrace(http.DefaultClient, "POST", "http://temba.io/4/", nil, nil, retries)
	assert.NoError(t, err)
	assert.Equal(t, 502, trace.Response.StatusCode)

	// unless idempotency declared via request header
	trace, err = httpx.DoTrace(http.DefaultClient, "POST", "http://temba.io/5/", nil, map[string]string{"Idempotency-Key": "123"}, retries)
	assert.NoError(t, err)
	assert.Equal(t, 200, trace.Response.StatusCode)

	// a retry config which can make 2 attempts (need a longer delay so that the Retry-After header value can be used)
	retries = httpx.NewFixedRetries(1 * time.Second)

	// retrying due to Retry-After header
	trace, err = httpx.DoTrace(http.DefaultClient, "POST", "http://temba.io/6/", nil, nil, retries)
	assert.NoError(t, err)
	assert.Equal(t, 201, trace.Response.StatusCode)

	// ignoring Retry-After header when it's too long
	trace, err = httpx.DoTrace(http.DefaultClient, "GET", "http://temba.io/7/", nil, nil, retries)
	assert.NoError(t, err)
	assert.Equal(t, 429, trace.Response.StatusCode)

	assert.False(t, mocks.HasUnused())
}

func TestParseRetryAfter(t *testing.T) {
	defer dates.SetNowSource(dates.DefaultNowSource)

	dates.SetNowSource(dates.NewFixedNowSource(time.Date(2020, 1, 7, 15, 10, 30, 500000000, time.UTC)))

	assert.Equal(t, 0*time.Second, httpx.ParseRetryAfter("x"))
	assert.Equal(t, 0*time.Second, httpx.ParseRetryAfter("0"))
	assert.Equal(t, 10*time.Second, httpx.ParseRetryAfter("10"))
	assert.Equal(t, 10*time.Second, httpx.ParseRetryAfter("10"))
	assert.Equal(t, 4500*time.Millisecond, httpx.ParseRetryAfter("Wed, 07 Jan 2020 15:10:35 GMT")) // 4.5 seconds in future
	assert.Equal(t, 0*time.Second, httpx.ParseRetryAfter("Wed, 07 Jan 2020 15:10:25 GMT"))         // 5.5 seconds in the past
}
