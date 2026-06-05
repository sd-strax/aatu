package server

import "database/sql"

// sqlNoRowsSentinel is sql.ErrNoRows. Centralizing the import keeps
// individual handlers from re-importing database/sql.
var sqlNoRowsSentinel = sql.ErrNoRows
