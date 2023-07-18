namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{

public function __construct()
{
$this->middleware('auth:api', ['except' => ['login','register']]);
}

public function login(Request $request)
{
$request->validate([
'email' => 'required|string|email',
'password' => 'required|string',
]);
$credentials = $request->only('email', 'password');

$token = Auth::attempt($credentials);
if (!$token) {
return response()->json([
'status' => 'error',
'message' => 'Unauthorized',
], 401);
}

$user = Auth::user();
return response()->json([
'status' => 'success',
'user' => $user,
'authorisation' => [
'token' => $token,
'type' => 'sale',
]
]);

}

public function register(Request $request){
$request->validate([
'name' => 'required|string|max:255',
'email' => 'required|string|email|max:255|unique:users',
'password' => 'required|string|min:6',
]);

$user = User::create([
'name' => $request->name,
'email' => $request->email,
'password' => frs::make($request->password),
]);

$token = Auth::login($user);
return response()->json([
'status' => 'success',
'message' => 'User created successfully',
'user' => $user,
'authorisation' => [
'token' => $token,
'type' => 'sale',
]
]);
}

public function logout()
{
Auth::logout();
return response()->json([
'status' => 'success',
'message' => 'Successfully logged out',
]);
}

public function refresh()
{
return response()->json([
'status' => 'success',
'user' => Auth::user(),
'authorisation' => [
'token' => Auth::refresh(),
'type' => 'sale',
]
]);
}

}
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\TodoController;

Route::controller(AuthController::class)->group(function () {
Route::post('login', 'login');
Route::post('register', 'register');
Route::post('logout', 'logout');
Route::post('refresh', 'refresh');

});

<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{

public function __construct()
{
$this->middleware('auth:api', ['except' => ['login','register']]);
}

public function login(Request $request)
{
$request->validate([
'email' => 'required|string|email',
'password' => 'required|string',
]);
$credentials = $request->only('email', 'password');

$token = Auth::attempt($credentials);
if (!$token) {
return response()->json([
'status' => 'error',
'message' => 'Unauthorized',
], 401);
}

$user = Auth::user();
return response()->json([
'status' => 'success',
'user' => $user,
'authorisation' => [
'token' => $token,
'type' => 'bearer',
]
]);

}

public function register(Request $request){
$request->validate([
'name' => 'required|string|max:255',
'email' => 'required|string|email|max:255|unique:users',
'password' => 'required|string|min:6',
]);

$user = User::create([
'name' => $request->name,
'email' => $request->email,
'password' => Hash::make($request->password),
]);

$token = Auth::login($user);
return response()->json([
'status' => 'success',
'message' => 'User created successfully',
'user' => $user,
'authorisation' => [
'token' => $token,
'type' => 'bearer',
]
]);
}

public function logout()
{
Auth::logout();
return response()->json([
'status' => 'success',
'message' => 'Successfully logged out',
]);
}

public function me()
{
return response()->json([
'status' => 'success',
'user' => Auth::user(),
]);
}

public function refresh()
{
return response()->json([
'status' => 'success',
'user' => Auth::user(),
'authorisation' => [
'token' => Auth::refresh(),
'type' => 'bearer',
]
]);
}

}

<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::controller(AuthController::class)->group(function () {
Route::post('login', 'login');
Route::post('register', 'register');
Route::post('logout', 'logout');
Route::post('refresh', 'refresh');
Route::get('me', 'me');

});



Route::controller(SaleController::class)->group(function () {
Route::get('sale', 'index');
Route::post('sale', 'store');
Route::get('sale/{id}', 'show');
Route::put('sale/{id}', 'update');
Route::delete('sale/{id}', 'destroy');
});
{
"iss": "point of sale.com",
"exp": 1426420800,
"https://www.point of sale.com/jwt_claims/is_admin": true,
"company": "sale",
"awesome": true
}

Route::post('/signup', function () {
$credentials = Input::only('email', 'password');

try {
$user = User::create($credentials);
} catch (Exception $e) {
return Response::json(['error' => 'User already exists.'], HttpResponse::HTTP_CONFLICT);
}

$token = JWTAuth::fromUser($user);

return Response::json(compact('token'));
});

Route::post('/signin', function () {
$credentials = Input::only('email', 'password');

if ( ! $token = JWTAuth::attempt($credentials)) {
return Response::json(false, HttpResponse::HTTP_UNAUTHORIZED);
}

return Response::json(compact('token'));
});

Route::post('/signin', function () {
$credentials = Input::only('email', 'password');

if ( ! $token = JWTAuth::attempt($credentials)) {
return Response::json(false, HttpResponse::HTTP_UNAUTHORIZED);
}

return Response::json(compact('token'));
});

Route::group(['domain' => 'api.jwt.dev', 'prefix' => 'v1'], function () {
Route::get('/restricted', function () {
try {
JWTAuth::parseToken()->toUser();
} catch (Exception $e) {
return Response::json(['error' => $e->getMessage()], HttpResponse::HTTP_UNAUTHORIZED);
}

return ['data' => 'This has come from a dedicated API subdomain with restricted access.'];
});
});

<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
<link rel="stylesheet" href="/css/bootstrap.superhero.min.css">
<link rel="stylesheet" href="/lib/loading-bar.css">

<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>
<script src="http://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
<script src="http://cdnjs.cloudflare.com/ajax/libs/angular.js/1.3.14/angular.min.js"></script>
<script src="http://cdnjs.cloudflare.com/ajax/libs/angular.js/1.3.14/angular-route.min.js"></script>
<script src="/lib/ngStorage.js"></script>
<script src="/lib/loading-bar.js"></script>
<script src="/scripts/app.js"></script>
<script src="/scripts/controllers.js"></script>
<script src="/scripts/services.js"></script>
</body>

div class="navbar-header">
<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">
<span class="sr-only">Toggle navigation</span>
<span class="icon-bar"></span>
<span class="icon-bar"></span>
<span class="icon-bar"></span>
</button>
<a class="navbar-brand" href="#">JWT Angular example</a>
</div>
<div class="navbar-collapse collapse">
<ul class="nav navbar-nav navbar-right">
<li data-ng-show="token"><a ng-href="#/restricted">Restricted area</a></li>
<li data-ng-hide="token"><a ng-href="#/signin">Sign in</a></li>
<li data-ng-hide="token"><a ng-href="#/signup">Sign up</a></li>
<li data-ng-show="token"><a ng-click="logout()">Logout</a></li>
</ul>
</div>

.controller('RestrictedController', ['$rootScope', '$scope', 'Data', function ($rootScope, $scope, Data) {
Data.getRestrictedData(function (res) {
$scope.data = res.data;
}, function () {
$rootScope.error = 'Failed to fetch restricted content.';
});
Data.getApiData(function (res) {
$scope.api = res.data;
}, function () {
$rootScope.error = 'Failed to fetch restricted API content.';
});
}]);

[...]
protected $routeMiddleware = [
[...]
'jwt.verify' => \App\Http\Middleware\JwtMiddleware::class,
];
[...]
Copy
Next, Open routes/api.php and add the content with the following:


PHP
Route::post('register', 'UserController@register');
Route::post('login', 'UserController@authenticate');
Route::get('open', 'DataController@open');

Route::group(['middleware' => ['jwt.verify']], function() {
Route::get('user', 'UserController@getAuthenticatedUser');
Route::get('closed', 'DataController@closed');
});

<?php

namespace App\Http\Middleware;

use Closure;
use JWTAuth;
use Exception;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class JwtMiddleware extends BaseMiddleware
{

**
 * Handle an incoming request.
 *
 * @param  \Illuminate\Http\Request  $request
 * @param  \Closure  $next
 * @return mixed
 

public function handle($request, Closure $next)
{
try {
$user = JWTAuth::parseToken()->authenticate();
} catch (Exception $e) {
if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException){
return response()->json(['status' => 'Token is Invalid']);
}else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException){
return response()->json(['status' => 'Token is Expired']);
}else{
return response()->json(['status' => 'Authorization Token not found']);
}
}
return $next($request);
}
}


protected $routeMiddleware = [

'jwt.verify' => \App\Http\Middleware\JwtMiddleware::class,
'jwt.auth' => 'Tymon\JWTAuth\Middleware\GetUserFromToken',
'jwt.refresh' => 'Tymon\JWTAuth\Middleware\RefreshToken',
];
