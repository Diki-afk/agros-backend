<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class ApiController extends Controller
{
    public function register(Request $request)
    {
        $data = $request->only('name', 'email', 'password', "role", "city_name");
        if ($request->role == "Admin") {
            $request->role = 1;
        }else{
            $request->role = 2;
        }
        $validator = Validator::make($data, [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'city_name' => 'required|string',
            'role' => 'required',
            'password' => 'required|string|min:6|max:50'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        $user = User::create([
        	'name' => $request->name,
        	'email' => $request->email,
        	'password' => bcrypt($request->password),
            'city_name' => $request->city_name,
            'role' => $request->role
        ]);
        
        return response()->json([
            'success' => true,
            'message' => 'User created successfully',
            'data' => $user
        ], Response::HTTP_OK);
    }
 
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        $validator = Validator::make($credentials, [
            'email' => 'required|email',
            'password' => 'required|string|min:6|max:50'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json([
                	'success' => false,
                	'message' => 'Login credentials are invalid.',
                ], 400);
            }else{

            }
        } catch (JWTException $e) {
    	return $credentials;
            return response()->json([
                	'success' => false,
                	'message' => 'Could not create token.',
                ], 500);
        }
 		//Token created, return with success response and jwt token
        return response()->json([
            'success' => true,
            'token' => $token,
        ]);
    }
 
    public function logout(Request $request)
    {
        //valid credential
        $validator = Validator::make($request->only('token'), [
            'token' => 'required'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        try {
            JWTAuth::invalidate($request->token);
 
            return response()->json([
                'success' => true,
                'message' => 'User has been logged out'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
 
    public function getUser(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);
 
        $user = JWTAuth::authenticate($request->token);
 
        return response()->json(['user' => $user]);
    }

    public function updateUser(Request $request)
    {
        $this->validate($request, [
            'token' => 'required',
            'name' => 'required|string',
            'city_name' => 'required|string',
            'password' => 'required|string|min:6|max:50'
        ]);
        $user = JWTAuth::authenticate($request->token);
        $user->update([
        	'name' => $request->name,
        	'city_name' => $request->city_name,
        	'password' => bcrypt($request->password)
        ]);
        return response()->json([
            'success' => true,
            'message' => 'User Update successfully',
            'data' => $user,
            'token' => $request->token
        ], Response::HTTP_OK);
    }

    public function getAllUser(Request $request)
    {
        $users = User::all();
 
        return response()->json(['user' => $users]);
    }

    public function deleteUser(Request $request)
    {
        $this->validate($request, [
            'token' => 'required',
            'id' => 'required|integer'
        ]);
        
        $admin = JWTAuth::authenticate($request->token);
        if ($admin->role == 1) {
            $user = User::find($request->id);
            $user->delete();
            return response()->json([
                'success' => true,
                'message' => 'User Deleted successfully',
            ], Response::HTTP_OK);
        }else {
            return response()->json([
                'success' => false,
                'message' => 'You are not admin',
            ], 403);
        }
    }
}
