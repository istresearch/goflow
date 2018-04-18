package types

import (
	"time"

	"github.com/nyaruka/goflow/utils"
)

// XDateTime is a datetime value
type XDateTime struct {
	baseXPrimitive

	native time.Time
}

// NewXDateTime creates a new date
func NewXDateTime(value time.Time) XDateTime {
	return XDateTime{native: value}
}

// Reduce returns the primitive version of this type (i.e. itself)
func (x XDateTime) Reduce() XPrimitive { return x }

// ToXText converts this type to text
func (x XDateTime) ToXText() XText { return NewXText(utils.DateToISO(x.Native())) }

// ToXBoolean converts this type to a bool
func (x XDateTime) ToXBoolean() XBoolean { return NewXBoolean(!x.Native().IsZero()) }

// ToXJSON is called when this type is passed to @(json(...))
func (x XDateTime) ToXJSON() XText { return MustMarshalToXText(utils.DateToISO(x.Native())) }

// Native returns the native value of this type
func (x XDateTime) Native() time.Time { return x.native }

// Compare compares this date to another
func (x XDateTime) Compare(other XDateTime) int {
	switch {
	case x.Native().Before(other.Native()):
		return -1
	case x.Native().After(other.Native()):
		return 1
	default:
		return 0
	}
}

// MarshalJSON is called when a struct containing this type is marshaled
func (x XDateTime) MarshalJSON() ([]byte, error) {
	return x.Native().MarshalJSON()
}

// UnmarshalJSON is called when a struct containing this type is unmarshaled
func (x *XDateTime) UnmarshalJSON(data []byte) error {
	nativePtr := &x.native
	return nativePtr.UnmarshalJSON(data)
}

// XDateTimeZero is the zero time value
var XDateTimeZero = NewXDateTime(time.Time{})
var _ XPrimitive = XDateTimeZero
