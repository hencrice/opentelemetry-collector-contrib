// Copyright 2019, OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package translator

import (
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/conventions"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awsxrayreceiver/internal/tracesegment"
)

func addSQLToSpan(sql *tracesegment.SQLData, attrs *pdata.AttributeMap) error {
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/master/exporter/awsxrayexporter/translator/sql.go#L33
	if sql != nil {
		if sql.URL != nil {
			dbURL, dbName, err := splitSQLURL(*sql.URL)
			if err != nil {
				return err
			}
			attrs.UpsertString(conventions.AttributeDBConnectionString, dbURL)
			attrs.UpsertString(conventions.AttributeDBName, dbName)
		}
		// not handling sql.ConnectionString for now because the X-Ray exporter
		// does not support it

		addString(sql.DatabaseType, conventions.AttributeDBSystem, attrs)
		addString(sql.SanitizedQuery, conventions.AttributeDBStatement, attrs)
		addString(sql.User, conventions.AttributeDBUser, attrs)
	}
	return nil
}

func splitSQLURL(rawURL string) (string, string, error) {
	li := strings.LastIndex(rawURL, "/")
	if li == -1 {
		return "", "", fmt.Errorf(
			"failed to parse out the database name in the \"sql.url\" field, rawUrl: %s",
			rawURL,
		)
	}
	return rawURL[:li], rawURL[li+1:], nil
}