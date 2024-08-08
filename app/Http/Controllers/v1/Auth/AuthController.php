<?php

namespace App\Http\Controllers\v1\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Hashing\BcryptHasher;
use JWTAuth;
use App\Models\User;
use Validator;
use Carbon\Carbon;
use Artisan;
use App\Models\Flush;
use DB;
use App\Models\Otp;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{
    public function login(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 500);
        }
        $user = User::where('email', $request->email)->first();
        if(!$user) return response()->json(['error' => 'User not found.'], 500);
        if (!(new BcryptHasher)->check($request->input('password'), $user->password)) {
            return response()->json(['error' => 'Email or password is incorrect. Authentication failed.'], 401);
        }
        $credentials = $request->only('email', 'password');
        try {
            JWTAuth::factory()->setTTL(40320); // Expired Time 28days
            if (! $token = JWTAuth::attempt($credentials, ['exp' => Carbon::now()->addDays(28)->timestamp])) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }
        return response()->json(['user' => $user,'token'=>$token,'status'=>200], 200);
    }

    public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'first_name'=>'required',
            'last_name'=>'required',
            'mobile'=>'required',
            'country_code'=>'required',
            'password' => 'required',
            'cover' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 500);
        }
        $user = User::create([
            'first_name' => $request->first_name,
            'last_name' => $request->last_name,
            'cover' => $request->cover,
            'country_code' => $request->country_code,
            'mobile' => $request->mobile,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = JWTAuth::fromUser($user);
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

    public function logout(){
        Auth::logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function get_admin(Request $request){
        $data = User::where('type','=',0)->first();
        if (is_null($data)) {
            $response = [
                'success' => false,
                'message' => 'Data not found.',
                'status' => 404
            ];
            return response()->json($response, 404);
        }
        $response = [
            'data'=>true,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function create_admin_account(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'first_name'=>'required',
            'last_name'=>'required',
            'mobile'=>'required',
            'country_code'=>'required',
            'password' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 500);
        }
        $emailValidation = User::where('email',$request->email)->first();
        if (is_null($emailValidation) || !$emailValidation) {

            $matchThese = ['country_code' => $request->country_code, 'mobile' => $request->mobile];
            $data = User::where($matchThese)->first();
            if (is_null($data) || !$data) {
                $checkExistOrNot = User::where('type','=',0)->first();

                if (is_null($checkExistOrNot)) {
                    $user = User::create([
                        'email' => $request->email,
                        'first_name'=>$request->first_name,
                        'last_name'=>$request->last_name,
                        'type'=>0,
                        'status'=>1,
                        'mobile'=>$request->mobile,
                        'cover'=>'NA',
                        'country_code'=>$request->country_code,
                        'gender'=>1,
                        'password' => Hash::make($request->password),
                    ]);

                    $token = JWTAuth::fromUser($user);
                    return response()->json(['user'=>$user,'token'=>$token,'status'=>200], 200);
                }

                $response = [
                    'success' => false,
                    'message' => 'Account already setuped',
                    'status' => 500
                ];
                return response()->json($response, 500);
            }

            $response = [
                'success' => false,
                'message' => 'Mobile is already registered.',
                'status' => 500
            ];
            return response()->json($response, 500);
        }
        $response = [
            'success' => false,
            'message' => 'Email is already taken',
            'status' => 500
        ];
        return response()->json($response, 500);
    }

    public function adminLogin(Request $request){
        $user = User::where('email', $request->email)->first();

        if(!$user) return response()->json(['error' => 'User not found.'], 500);

        // Account Validation
        if (!(new BcryptHasher)->check($request->input('password'), $user->password)) {

            return response()->json(['error' => 'Email or password is incorrect. Authentication failed.'], 401);
        }

        if($user->type == 1){
            return response()->json(['error' => 'access denied'], 401);
        }
        // Login Attempt
        $credentials = $request->only('email', 'password');

        try {

            JWTAuth::factory()->setTTL(40320); // Expired Time 28days

            if (! $token = JWTAuth::attempt($credentials, ['exp' => Carbon::now()->addDays(28)->timestamp])) {

                return response()->json(['error' => 'invalid_credentials'], 401);

            }
        } catch (JWTException $e) {

            return response()->json(['error' => 'could_not_create_token'], 500);

        }
        return response()->json(['user' => $user,'token'=>$token,'status'=>200], 200);
    }

    public function uploadImage(Request $request){
        $validator = Validator::make($request->all(), [
            'image' => 'required|image:jpeg,png,jpg,gif,svg|max:2048'
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 505);
        }
        Artisan::call('storage:link', []);
        $uploadFolder = 'images';
        $image = $request->file('image');
        $image_uploaded_path = $image->store($uploadFolder, 'public');
        $uploadedImageResponse = array(
            "image_name" => basename($image_uploaded_path),
            "mime" => $image->getClientMimeType()
        );
        $response = [
            'data'=>$uploadedImageResponse,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function uploadVideo(Request $request){
        ini_set('upload_max_filesize', '500M');
        ini_set('post_max_size', '500M');
        Artisan::call('storage:link', []);
        $uploadFolder = 'video';
        $image = $request->file('video');
        $image_uploaded_path = $image->store($uploadFolder, 'public');
        $uploadedImageResponse = array(
            "image_name" => basename($image_uploaded_path),
            "mime" => $image->getClientMimeType()
        );
        $response = [
            'data'=>$uploadedImageResponse,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);

    }

    public function authors(Request $request){
        $data = User::where('type',2)->get();
        $response = [
            'data'=>$data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function create_new_author(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'first_name'=>'required',
            'last_name'=>'required',
            'cover'=>'required',
            'mobile'=>'required',
            'country_code'=>'required',
            'password' => 'required',
            'roles'=>'required'
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 500);
        }
        $emailValidation = User::where('email',$request->email)->first();
        if (is_null($emailValidation) || !$emailValidation) {

            $matchThese = ['country_code' => $request->country_code, 'mobile' => $request->mobile];
            $data = User::where($matchThese)->first();
            if (is_null($data) || !$data) {

                $user = User::create([
                    'email' => $request->email,
                    'first_name'=>$request->first_name,
                    'last_name'=>$request->last_name,
                    'type'=>2,
                    'status'=>1,
                    'mobile'=>$request->mobile,
                    'cover'=>$request->cover,
                    'country_code'=>$request->country_code,
                    'roles'=>$request->roles,
                    'password' => Hash::make($request->password),
                ]);

                $token = JWTAuth::fromUser($user);
                return response()->json(['user'=>$user,'token'=>$token,'status'=>200], 200);

            }

            $response = [
                'success' => false,
                'message' => 'Mobile is already registered.',
                'status' => 500
            ];
            return response()->json($response, 500);
        }
        $response = [
            'success' => false,
            'message' => 'Email is already taken',
            'status' => 500
        ];
        return response()->json($response, 500);
    }

    public function deleteUser(Request $request){
        $validator = Validator::make($request->all(), [
            'id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 500);
        }
        $data = User::find($request->id);
        if ($data) {
            $data->delete();
            $response = [
                'data'=>$data,
                'success' => true,
                'status' => 200,
            ];
            return response()->json($response, 200);
        }
        $response = [
            'success' => false,
            'message' => 'Data not found.',
            'status' => 404
        ];
        return response()->json($response, 404);
    }

    public function update(Request $request){
        $validator = Validator::make($request->all(), [
            'id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 404);
        }
        $data = User::find($request->id)->update($request->all());
        if (is_null($data)) {
            $response = [
                'success' => false,
                'message' => 'Data not found.',
                'status' => 404
            ];
            return response()->json($response, 404);
        }
        $response = [
            'data'=>$data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);

    }

    public function getInfo(Request $request){
        $validator = Validator::make($request->all(), [
            'id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 500);
        }
        $data = User::find($request->id);
        $response = [
            'data'=>$data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function emailExist(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 404);
        }

        $data = User::where('email',$request->email)->first();

        if (is_null($data)) {
            $response = [
                'data' => false,
                'message' => 'Data not found.',
                'status' => 404
            ];
            return response()->json($response, 404);
        }

        $mail = $request->email;
        $username = $request->email;
        $subject = $request->subject;
        $otp = random_int(100000, 999999);
        $savedOTP = Otp::create([
            'otp'=>$otp,
            'key'=>$request->email,
            'status'=>0,
        ]);
        $generalInfo = Flush::take(1)->first();
        if (is_null($generalInfo)) {
            $response = [
                'success' => false,
                'message' => 'Something went wrong with administrator',
                'status' => 404
            ];
            return response()->json($response, 404);
        }
        $emailSettings =  json_decode($generalInfo->value);
        $mailTo = Mail::send('mails/reset',
            [
            'app_name'      => $emailSettings->name,
            'otp'          => $otp
            ]
            , function($message) use($mail,$username,$subject,$emailSettings){
            $message->to($mail, $username)
            ->subject($subject);
            $message->from($emailSettings->email,$emailSettings->name);
        });

        $response = [
            'data'=>true,
            'mail'=>$mailTo,
            'otp_id'=>$savedOTP->id,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function updateUserPasswordWithEmail(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
            'id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 404);
        }

        $match =  ['key'=>$request->email,'id'=>$request->id];
        $data = Otp::where($match)->first();
        if (is_null($data)) {
            $response = [
                'success' => false,
                'message' => 'Data not found.',
                'status' => 404
            ];
            return response()->json($response, 404);
        }

        $updates = User::where('email',$request->email)->first();
        $updates->update(['password'=>Hash::make($request->password)]);

        if (is_null($updates)) {
            $response = [
                'success' => false,
                'message' => 'Data not found.',
                'status' => 404
            ];
            return response()->json($response, 404);
        }

        $response = [
            'data'=>true,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getUsers(Request $request){
        $data = User::where('type',1)->get();
        $response = [
            'data'=>$data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function sendNoficationGlobal(Request $request){
        try {
            $validator = Validator::make($request->all(), [
                'title' => 'required',
                'message' => 'required',
                'cover'  => 'required'
            ]);
            if ($validator->fails()) {
                $response = [
                    'success' => false,
                    'message' => 'Validation Error.', $validator->errors(),
                    'status'=> 500
                ];
                return response()->json($response, 404);
            }

            $data = Flush::where('key','web-settings')->first();
            if ($data) {
                $fcmData =json_decode($data['value']);
                $allIds = DB::table('fcm_token')->select('fcm_token')->get();
                $fcm_ids = array();
                foreach($allIds as $i => $i_value) {
                    if($i_value->fcm_token !='NA'){
                        array_push($fcm_ids,$i_value->fcm_token);
                    }
                }

                if (is_null($data)) {
                    $response = [
                        'data' => false,
                        'message' => 'Data not found.',
                        'status' => 404
                    ];
                    return response()->json($response, 200);
                }
                $fcm_ids  = array_unique($fcm_ids);
                $regIdChunk=array_chunk($fcm_ids,1000);
                foreach($regIdChunk as $RegId){
                    $header = array();
                    $header[] = 'Content-type: application/json';
                    $header[] = 'Authorization: key=' . $fcmData->fcm_token;

                    $payload = [
                        'registration_ids' => $RegId,
                        'priority'=>'high',
                        'notification' => [
                        'title' => $request->title,
                        'body' => $request->message,
                        'image'=>$request->cover,
                        "sound" => "wave.wav",
                        "channelId"=>"fcm_default_channel"
                        ],
                        'android'=>[
                            'notification'=>[
                                "sound" => "wave.wav",
                                "defaultSound"=>true,
                                "channelId"=>"fcm_default_channel"
                            ]
                        ]
                    ];

                    $crl = curl_init();
                    curl_setopt($crl, CURLOPT_HTTPHEADER, $header);
                    curl_setopt($crl, CURLOPT_POST,true);
                        curl_setopt($crl, CURLOPT_URL, 'https://fcm.googleapis.com/fcm/send');
                    curl_setopt($crl, CURLOPT_POSTFIELDS, json_encode( $payload ) );

                    curl_setopt($crl, CURLOPT_RETURNTRANSFER, true );

                    $rest = curl_exec($crl);
                    if ($rest === false) {
                        return curl_error($crl);
                    }
                    curl_close($crl);
                }
            }

            $response = [
                'success' => true,
                'status' => 200,
            ];
            return response()->json($response, 200);
        } catch (Exception $e) {
            return response()->json($e->getMessage(),200);
        }
    }
}
