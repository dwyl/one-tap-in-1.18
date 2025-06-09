# Add Google One Tap to the Authentication Generated Code

The latest 1.18 is in RC and `phx.gen.auth` ships with magic links enabled for login and registration (among other goodies).

Source: <https://www.phoenixframework.org/blog/phoenix-1-8-released>


The latest Phoenix version has been installed  - at the time of writting - with:

```sh
mix archive.install hex phx_new 1.8.0-rc.3 --force
```

We want to add thee Google One tap login into the authentication funnel.


## Code generator:

Use the Phoenix code generator:

```sh
mix phx.new my_app

mix phx.gen.auth Accounts User users
```

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

  def mount(_params, %{"_csrf_token" => _csrf_token} = _session, socket) do
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

When Google One Tap POSTs the credential to your "/google_auth" endpoint, a malicious site could try to forge such a request.
The plug checks that a CSRF token set in a cookie (by your app) matches the one sent in the POST params.
This ensures the POST is coming from your own frontend, not a third-party site.

Google's Recommendation:
Google recommends verifying the CSRF token for One Tap and Sign-In With Google flows.

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

  #### PEM version ####

  defp pem_certs, do: "https://www.googleapis.com/oauth2/v1/certs"

  defp check_identity_v1(jwt) do
    with {:ok, %{"kid" => kid, "alg" => alg}} <- Joken.peek_header(jwt),
         {:ok, body} <- fetch(pem_certs()) do
      {true, %{fields: fields}, _} =
        body
        |> Map.get(kid)
        |> JOSE.JWK.from_pem()
        |> JOSE.JWT.verify_strict([alg], jwt)

      {:ok, fields}
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


