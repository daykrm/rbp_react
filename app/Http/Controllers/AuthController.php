<?php

namespace App\Http\Controllers;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    //
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);

        $credentials = request(['email', 'password']);
        $responseMessage = 'Invalid username or password';

        if (!Auth::attempt($credentials)) return response()->json([
            'success' => false,
            'message' => $responseMessage,
            'error' => $responseMessage
        ], 422);

        //Get current authenticated user
        $user = $request->user();

        $accessToken = $user->createToken('authToken')->accessToken;
        $responseMessage = 'Login Successfully';

        return $this->respondWithToken($accessToken, $responseMessage, $user);

        // $tokenResult = $user->createToken('Personal Access Token');
        // $token = $tokenResult->token;

        // if ($request->remember_me) $token->expires_at = Carbon::now()->addWeeks(1);

        // $token->save();

        // $data = [
        //     'access_token' => $tokenResult->accessToken,
        //     'token_type' => 'Bearer',
        //     'expires_at' => Carbon::parse(
        //         $tokenResult->token->expires_at
        //     )->toDateTimeString()
        // ];

        // return response()->json($data);
    }

    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);

        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $user->save();

        return response()->json(['message', 'Successfully created user'], 201);
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();

        return response()->json([
            'success' => true,
            'message' => 'Successfully logged out'
        ], 200);
    }

    public function user(Request $request)
    {
        return response()->json([
            'success' => true,
            'message' => 'User profile',
            'data' => $request->user()
        ], 200);
    }
}
