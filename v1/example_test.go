package v1_test

import (
	"fmt"

	"github.com/cnuss/libtunnel"
)

// New returns an unconfigured Builder. Configure it with the With* methods and
// finalize with Build.
func ExampleNew() {
	res := libtunnel.New[string]().
		WithName("greeting").
		WithValue("hello").
		Build()

	fmt.Printf("%s = %q\n", res.Name, res.Value)
	// Output: greeting = "hello"
}

// WithValue sets the payload; the name is optional. Built without WithName, the
// Result's Name is empty.
func Example_value() {
	res := libtunnel.New[int]().WithValue(42).Build()

	fmt.Printf("name=%q value=%d\n", res.Name, res.Value)
	// Output: name="" value=42
}

// The zero value of T is returned when WithValue is never called.
func Example_zeroValue() {
	res := libtunnel.New[int]().WithName("count").Build()

	fmt.Printf("name=%q value=%d\n", res.Name, res.Value)
	// Output: name="count" value=0
}
