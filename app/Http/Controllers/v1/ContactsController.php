<?php

namespace App\Http\Controllers\v1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use App\Models\Contacts;
use App\Models\Flush;
use Carbon\Carbon;
use Validator;
use DB;

class ContactsController extends Controller
{
    public function save(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required',
            'message' => 'required',
            'date'=> 'required'
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 404);
        }

        $data = Contacts::create($request->all());
        if (is_null($data)) {
            $response = [
            'data'=>$data,
            'message' => 'error',
            'status' => 500,
        ];
        return response()->json($response, 200);
        }
        $response = [
            'data'=>$data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getById(Request $request){
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

        $data = Contacts::find($request->id);

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
        $data = Contacts::find($request->id)->update($request->all());

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

    public function delete(Request $request){
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
        $data = Contacts::find($request->id);
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

    public function getAll(){
        $data = Contacts::orderBy('id','desc')->get();
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

    public function sendMailToAdmin(Request $request){

        try {
            $validator = Validator::make($request->all(), [
                'subject' => 'required',
                'thank_you_text' => 'required',
                'header_text' => 'required',
                'from_mail' =>'required',
                'from_username' => 'required',
                'from_message' => 'required',
                'email' =>'required',
                'to_respond'=>'required',
                'id'=>'required'
            ]);
            if ($validator->fails()) {
                $response = [
                    'success' => false,
                    'message' => 'Validation Error.', $validator->errors(),
                    'status'=> 500
                ];
                return response()->json($response, 404);
            }
            $mail = $request->email;
            $username = $request->from_username;
            $subject = $request->subject;
            $toMail = $request->from_mail;

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
            $data = Mail::send('mails/contact',
             [
                'app_name'      =>$emailSettings->name,
                'date'          => Carbon::now()->year,
                'email'         =>$request->from_mail,
                'name'          =>$request->from_username,
                'contents'       =>$request->from_message,
             ]
             , function($message) use($mail,$username,$subject,$emailSettings){
                $message->to($mail, $username)
                ->subject($subject);
                $message->from($emailSettings->email,$emailSettings->name);
            });
            $mailTo = Mail::send('mails/respond',
             [
                'app_name'      => $emailSettings->name,
                'respond'        =>$request->to_respond
             ]
             , function($message) use($mail,$username,$subject,$emailSettings){
                $message->to($mail, $username)
                ->subject($subject);
                $message->from($emailSettings->email,$emailSettings->name);
            });
            $response = [
                'success' => $data,
                'message' => 'success',
                'status' => 200
            ];
            return $response;
        } catch (Exception $e) {
            return response()->json($e->getMessage(),200);
        }
    }

    public function replyContactForm(Request $request){

        try {
            $validator = Validator::make($request->all(), [
                'subject' => 'required',
                'thank_you_text' => 'required',
                'header_text' => 'required',
                'email' =>'required',
                'from_username' =>'required',
                'to_respond'=>'required',
                'id'=>'required'
            ]);
            if ($validator->fails()) {
                $response = [
                    'success' => false,
                    'message' => 'Validation Error.', $validator->errors(),
                    'status'=> 500
                ];
                return response()->json($response, 404);
            }
            $mail = $request->email;
            $username = $request->from_username;
            $subject = $request->subject;

            $toMail = $request->from_mail;

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

            $mailTo = Mail::send('mails/respond',
             [
                'app_name'      => $emailSettings->name,
                'respond'        =>$request->to_respond
             ]
             , function($message) use($mail,$username,$subject,$emailSettings){
                $message->to($mail, $username)
                ->subject($subject);
                $message->from($emailSettings->email,$emailSettings->name);
            });
            $response = [
                'success' => $mailTo,
                'message' => 'success',
                'status' => 200
            ];
            return $response;
        } catch (Exception $e) {
            return response()->json($e->getMessage(),200);
        }
    }
}
