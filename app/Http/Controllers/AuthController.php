<?php
    namespace App\Http\Controllers;

    use App\Http\Requests\RegisterAuthRequest;
    use App\Models\User;
    use Illuminate\Http\Request;
    use JWTAuth;
    use Tymon\JWTAuth\Exceptions\JWTException;
    // use Tymon\JWTAuth\AuthController;

class AuthController extends Controller {
    public $loginAfterSignUp = true;

    public function register(Request $request) {
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();
        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }
        return response()->json([
        'status' => 'ok',
        'data' => $user
        ], 200);
    }
    public function login(Request $request) {
        $input = $request->only('email', 'password');
        $jwt_token = null;

        if (!$jwt_token = JWTAuth::attempt($input)) {
            return response()->json([
            'status' => 'invalid_credentials',
            'message' => 'Invalid Credentials',
            ], 401);
        }
        return response()->json([
        'status' => 'ok',
        'token' => $jwt_token,
        ]);
    }

    public function logout(Request $request) {
        $this->validate($request, [
        'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);
            return response()->json([
            'status' => 'ok',
            'message' => 'Logout Successfuly'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
            'status' => 'unknown_error',
            'message' => 'An unknown error has occured.'
            ], 500);
        }
    }

    public function getAuthUser(Request $request) {
        $this->validate($request, [
        'token' => 'required'
        ]);
        $user = JWTAuth::authenticate($request->token);
        return response()->json(['user' => $user]);
    }

    protected function jsonResponse($data, $code = 200) {
        return response()->json($data, $code,
        ['Content-Type' => 'application/json;charset=UTF8', 'Charset' => 'utf-8'], JSON_UNESCAPED_UNICODE);
    }
}