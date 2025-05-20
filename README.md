example usage:

```
auto query_performance_counter_fn = jmport::module( L"kernel32.dll" )[ "QueryPerformanceCounter" ].as<BOOL( * )( LARGE_INTEGER* )>( );

LARGE_INTEGER counter{};
query_performance_counter_fn( &counter );

printf( "count: %lld\n", counter.QuadPart );
```
