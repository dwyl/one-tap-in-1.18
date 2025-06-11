# Add Google One Tap to the Authentication Generated Code

The latest 1.8 is in RC and `phx.gen.auth` ships with magic links enabled for login and registration (among other goodies).

Source: <https://www.phoenixframework.org/blog/phoenix-1-8-released>


The latest Phoenix version has been installed  - at the time of writting - with:

```sh
mix archive.install hex phx_new 1.8.0-rc.3 --force
```

We want to add the Google One tap login into the authentication funnel.

We build on top of the existing generated code and use the `UserAuth` module. 

The UI is simple: it uses the ready-to-use Google One Tap button that wether re-uses your browser account (if logged-in) or goes through a Google login process.

We introduce two modules: a CSRF check module and a JWT check module against Google's public certs and a "bonus" for the CSP rules (curiously, Google does it wrong because they inject <style> elements that demands "unsafe-inline" !!).


## Preliminary: Triggering a Phoenix controller action from a form in a LiveView

This blog <https://fly.io/phoenix-files/phx-gen-auth/> explains how to _set a cookie from a LiveView form_. 
With more details: <https://fly.io/phoenix-files/phx-trigger-action/>

> The LiveView lifecycle starts as an HTTP request, but then a WebSocket connection is established with the server, and all communication between your LiveView and the server takes place over that connection.
> Why is this important? Because session data is stored in cookies, and cookies are only exchanged during an HTTP request/response. So writing data in session can’t be done directly from a LiveView"

LiveView documentation: <https://hexdocs.pm/phoenix_live_view/form-bindings.html#submitting-the-form-action-over-http>

```elixir
<.form
  :let={f}
  for={@form}
  id="login_form_magic"
  action={~p"/users/log-in"}
  phx-submit="submit_magic"
>
```

The "action" attribute will execute the HTTP request served at the URI "/users/log-in" which is `:create`.

## Code generator:

Use the Phoenix code generator:

```sh
mix phx.new my_app

mix phx.gen.auth Accounts User users
```

and then run the migrations.

## Config

### Google cloud setup

- the Google CLIENT_ID that you obtained from the <https://console.cloud.google.com>

Path: 
- API & Services/Credentials/Create Credentials/OAuth client ID
- Application type: Web Application
- Authorized JavaScript origins: http://localhost:4000
- Authorized redirect URIs: http://localhost:4000:google_auth 

![Screenshot 2025-06-08 at 21 54 04](https://github.com/user-attachments/assets/3f284b5c-f3eb-465c-a114-81b2e0495a9f)

### App config

Set the Google credentials and endpoint where Google will post the JWT in your config:

```elixir
# /config/runtime.exs
config :my_app,
  google_client_id:
    System.get_env("GOOGLE_CLIENT_ID") ||
      raise("""
      environment variable GOOGLE_CLIENT_ID is missing.
      You can generate one by going to https://console.cloud.google.com/apis/credentials
      and creating a new OAuth 2.0 Client ID.
      """),
  google_callback_uri: "/google_auth"
```

> you can create an `.env` file where you `export GOOGLE_CLIENT_ID` and run `source .env`.

## The UI

Firstly, the UI. Define a link next to the "Register" and "Log In" links:

```html
<!-- root.html.heex -->

<body>
    <ul class="menu menu-horizontal w-full relative z-10 flex items-center gap-4 px-4 sm:px-6 lg:px-8 justify-end">
      <%= if @current_scope do %>
        <li>
          {@current_scope.user.email}
        </li>
        <li>
          <.link href={~p"/users/settings"}>Settings</.link>
        </li>
        <li>
          <.link href={~p"/users/log-out"} method="delete">Log out</.link>
        </li>
      <% else %>

        <<<
        <li class="badge">
          <.link href={~p"/users/one-tap"}>One Tap</.link>
        </li>
        >>>

        <li class="badge">
          <.link href={~p"/users/register"}>Register</.link>
        </li>
        <li class="badge">
          <.link href={~p"/users/log-in"}>Log in</.link>
        </li>
      <% end %>
    </ul>
```

You see the screen below:

![Screenshot 2025-06-08 at 19 37 31](https://github.com/user-attachments/assets/d4c7a94a-b95c-4edb-94cf-843b2265e426)

Add the corresponding route:

```elixir
# router.ex
scope "/", MyAppWeb do
    pipe_through [:browser]

    live_session :current_user,
      on_mount: [{MyAppWeb.UserAuth, :mount_current_scope}] do
      live "/users/register", UserLive.Registration, :new
      live "/users/log-in", UserLive.Login, :new
      live "/users/log-in/:token", UserLive.Confirmation, :new

      <<<
      live "/users/one-tap", UserLive.OneTap
       >>>
    end

    post "/users/log-in", UserSessionController, :create
    delete "/users/log-out", UserSessionController, :delete
end
```

Define the corresponding LiveView to this `GET` route. It brings in the Google One Tap script and fills in the CLIENT_ID and CALLBACK_URI from the assigns whose values are taken from the `config`:

```elixir
defmodule MyAppWeb.UserLive.OneTap do
  use MyAppWeb, :live_view

  def render(assigns) do
    ~H"""
    <div id="one-tap-login" phx-update="ignore">
      <script src="https://accounts.google.com/gsi/client" async>
      </script>

      <div
        id="g_id_onload"
        data-client_id={@g_client_id}
        data-login_uri={@g_cb_uri}
        data-auto_prompt="true"
      >
      </div>
      <div
        class="g_id_signin"
        data-type="standard"
        data-text="signin_with"
        data-shape="rectangular"
        data-theme="outline"
        data-size="large"
        data-logo_alignment="center"
        data-width="200"
      >
      </div>
    </div>
    """
  end

  def mount(_params, _session, socket) do
    callback_uri =
      Path.join(
        MyAppWeb.Endpoint.url(),
        Application.fetch_env!(:my_app, :google_callback_uri)
      )

    google_client_id =
      Application.fetch_env!(:my_app, :google_client_id)

    socket =
      assign(socket,
        g_cb_uri: callback_uri,
        g_client_id: google_client_id
      )

    {:ok, socket}
  end
end
```

Add a pipeline for a POST route that goes through a custom `Plug`. It will receive the JWT sent by Google.

```elixir
# router.ex

scope "/", MyAppWeb do
    pipe_through [:google_auth]
    post "/google_auth", OneTapController, :handle
end
```

## CSRF Protection:

This checks that the POST to "/google_auth" is coming from the frontend, not from a third-party site.
For this, it checks that a CSRF token in a cookie (set by the server) matches the one in the POST params.

This is a Google's Recommendation.

```elixir
# plug_google_auth.ex

defmodule MyAppWeb.PlugGoogleAuth do
  @moduledoc """
  Plug to check the CSRF state concordance when receiving data from Google.

  Denies to treat the HTTP request if fails.
  """
  import Plug.Conn
  use MyAppWeb, :verified_routes
  use MyAppWeb, :controller

  def init(opts), do: opts

  def call(conn, _opts) do
    g_csrf_from_cookies =
      fetch_cookies(conn)
      |> Map.get(:cookies, %{})
      |> Map.get("g_csrf_token")

    g_csrf_from_params =
      Map.get(conn.params, "g_csrf_token")

    case {g_csrf_from_cookies, g_csrf_from_params} do
      {nil, _} ->
        halt_process(conn, "CSRF cookie missing")

      {_, nil} ->
        halt_process(conn, "CSRF token missing")

      {cookie, param} when cookie != param ->
        halt_process(conn, "CSRF token mismatch")

      _ ->
        conn
    end
  end

  defp halt_process(conn, msg) do
    conn
    |> fetch_session()
    |> fetch_flash()
    |> put_flash(:error, msg)
    |> redirect(to: ~p"/")
    |> halt()
  end
end
```

## JWT verification

This POST endpoint is served by a controller where you:

- Verify the JWT against Google public certs
- If succesfull, check if the user exists or create him,
- We reuse the `UserAuth` module:
    - Creates a session token for the user.
    - Stores the token in the session and (optionally) in a signed "remember me" cookie.
    - Redirects the user to the intended page or a default after login.


```elixir
defmodule MyAppWeb.OneTapController do
  use MyAppWeb, :controller
  alias MyAppWeb.UserAuth
  alias MyApp.Accounts

  def handle(conn, %{"credential" => jwt} = _params) do
    case ExGoogleCerts.verified_identity(%{jwt: jwt})  do
      {:ok, profile} ->
        user =
          case Accounts.get_user_by_email(profile["email"]) do
            nil ->
              {:ok, user} =
                Accounts.register_user(%{
                  email: profile["email"],
                  confirmed_at: if(profile["email_verified"], do: DateTime.utc_now(), else: nil)
                })

              user

            user ->
              user
          end

        conn
        |> fetch_session()
        |> fetch_flash()
        |> put_flash(:info, "Google identity verified successfully.")
        |> UserAuth.log_in_user(user)

      {:error, reason} ->
        conn
        |> fetch_session()
        |> fetch_flash()
        |> put_flash(:error, "Google identity verification failed: #{reason}")
        |> redirect(to: ~p"/")
    end
  end

  def handle(conn, %{}) do
    conn
    |> fetch_session()
    |> fetch_flash()
    |> put_flash(:error, "Protocol error, please contact the maintainer")
    |> redirect(to: ~p"/")
  end
end
```
This controller uses:
- the existing MyApp.UserAuth module,
- the existing MyApp.Accounts module,
- a custom module `ExGoogleCerts` that verifies the JWT against Google's public certs and extract the Google's profile from it:

```elixir
defmodule ExGoogleCerts do
  @moduledoc """
  This module provides functions to verify Google identity tokens using the Google public keys.
  """

  def verified_identity(%{jwt: jwt}) do
    with {:ok, profile} <- check_identity_v1(jwt),
         :ok <- run_checks(profile) do
      {:ok, profile}
    else
      {:error, msg} -> {:error, msg}
    end
  end


  defp iss, do: "https://accounts.google.com"
  defp app_id, do: System.get_env("GOOGLE_CLIENT_ID")

  #### Google recommendation: Oauth/V3 version ####

  defp jwk_certs, do: "https://www.googleapis.com/oauth2/v3/certs"

  def check_identity_v3(jwt) do
    with {:ok, %{"kid" => kid, "alg" => alg}} <- Joken.peek_header(jwt),
         {:ok, %{"keys" => certs}} <- fetch(jwk_certs()) do
      cert = Enum.find(certs, fn cert -> cert["kid"] == kid end)
      signer = Joken.Signer.create(alg, cert)
      Joken.verify(jwt, signer, [])
    else
      {:error, reason} -> {:error, inspect(reason)}
    end
  end



  # default HTTP client: Req (parses the body as JSON)
  defp fetch(url) do
    case Req.get(url) do
      {:ok, %{body: body}} ->
        {:ok, body}

      {:error, error} ->
        {:error, error}
    end
  end

  defp run_checks(claims) do
    %{
      "exp" => exp,
      "aud" => aud,
      "azp" => azp,
      "iss" => iss
    } = claims

    with {:ok, true} <- not_expired(exp),
         {:ok, true} <- check_iss(iss),
         {:ok, true} <- check_user(aud, azp) do
      :ok
    else
      {:error, message} -> {:error, message}
    end
  end

  defp not_expired(exp) do
    case exp > DateTime.to_unix(DateTime.utc_now()) do
      true -> {:ok, true}
      false -> {:error, :expired}
    end
  end

  defp check_user(aud, azp) do
    case aud == app_id() || azp == app_id() do
      true -> {:ok, true}
      false -> {:error, :wrong_id}
    end
  end

  defp check_iss(iss) do
    case iss == iss() do
      true -> {:ok, true}
      false -> {:ok, :wrong_issuer}
    end
  end
end
```

## Bonus: CSP

In the router, add a `Plug` function:

```elixir
def put_csp(conn, _) do
  csp_nonce = csp_nonce()
  conn
  |> put_resp_header(
    "content-security-policy",
    """
    default-src 'self' https://accounts.google.com;
    script-src https://accounts.google.com http://localhost:4000 'nonce-#{csp_nonce}';
    img-src 'self' data:;
    style-src 'self' 'unsafe-inline' https://accounts.google.com;
    frame-ancestors 'self' https://accounts.google.com;
    """
    |> String.replace("\n", " ")
  )
  |> assign(:csp_nonce, csp_nonce)
end

defp csp_nonce do
  nonce = 24
  |> :crypto.strong_rand_bytes()
  |> Base.encode64(padding: false)

  Process.put(:nonce, nonce)
  nonce
end
```

and use it in the pipelines `:browser` and `:google_auth`.

> the header `Referrer-Policy: no-referrer-when-downgrade` is demanded by Google.

```elixir
pipeline :browser do
  plug :accepts, ["html"]
  plug :fetch_session
  plug :fetch_live_flash
  plug :put_root_layout, html: {LiveFlightWeb.Layouts, :root}
  plug :put_csp
  plug :put_secure_browser_headers
  plug :protect_from_forgery
  plug :fetch_current_scope_for_user
end

pipeline :google_auth do
  plug :put_csp
  plug :put_secure_browser_headers, %{"referrer-policy" => "no-referrer-when-downgrade"}
  plug LiveFlightWeb.PlugGoogleAuth
end
```

Then, in the "OneTapController" that serves the live "/one-tap" route, add the "csp_nonce" that we saved in the Process registry:

```elixir
def mount(_,_,socket) do
  [...]
  csp_nonce = Process.get(:nonce)

  {:ok,
    assign(socket,
      g_cb_uri: callback_uri,
      g_client_id: google_client_id,
      csp_nonce: csp_nonce
  )}
end
```

and add the nonce to the script:

```elixir
def render(assigns) do
  ~H"""
  <div id="one-tap-login" phx-update="ignore">
    <script nonce={@csp_nonce} src="https://accounts.google.com/gsi/client" async>
    </script>
  [...]
  """
end
```

Since we passed the nonce to the "conn" assigns, we can also pass it to the script that runs the main file "app.js":

In "root.html.heex", we add:

```html
<script
  defer
  phx-track-static
  type="text/javascript"
  src={~p"/assets/js/app.js"}
  type="module"
  nonce={@csp_nonce}
>
```
