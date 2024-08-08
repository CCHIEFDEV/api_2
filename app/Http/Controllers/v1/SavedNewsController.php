<?php

namespace App\Http\Controllers\v1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\SavedNews;
use App\Models\NewsLikes;
use DB;
use Validator;

class SavedNewsController extends Controller
{
    public function save(Request $request){
        $validator = Validator::make($request->all(), [
            'news_id' => 'required',
            'uid' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 404);
        }

        $data = SavedNews::create($request->all());
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

        $data = SavedNews::find($request->id);

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
        $data = SavedNews::find($request->id)->update($request->all());

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
            'uid' => 'required',
            'news_id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 404);
        }
        $data = SavedNews::where(['news_id'=>$request->news_id,'uid'=>$request->uid])->first();
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
        $data = SavedNews::all();
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

    public function getSavedNews(Request $request){
        $validator = Validator::make($request->all(), [
            'uid' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.', $validator->errors(),
                'status'=> 500
            ];
            return response()->json($response, 404);
        }
        $data = DB::table('saved_news')
        ->select('saved_news.id as id','news.id as news_id','news.cate_id as cate_id','news.comments as comments','news.content as content','news.cover as cover',
        'news.created_at','news.extra_field as extra_field','news.likes as likes','news.share_content as share_content','news.short_descriptions as short_descriptions',
        'news.url_slugs as url_slugs','news.status as status','news.title as title','news.translations as translations','news.video_url as video_url',
        'categories.name as cate_name','categories.translations as cate_translations','categories.title_color as title_color',
        'cities.name as city_name','users.first_name as author_first_name','users.last_name as author_last_name')
        ->join('news','saved_news.news_id','news.id')
        ->join('categories', 'news.cate_id', '=', 'categories.id')
        ->join('cities', 'news.city_id', '=', 'cities.id')
        ->join('users', 'news.author_id', '=', 'users.id')
        ->orderBy('news.id','desc')
        ->where('saved_news.uid',$request->uid)
        ->get();
        foreach($data as $loop){
            $loop->uid = $request->uid;
            $temp = NewsLikes::where(['uid'=>$request->uid,'news_id'=>$loop->news_id])->first();
            if(isset($temp) && $temp->id){
                $loop->haveLiked = true;
            }else{
                $loop->haveLiked = false;
            }
        }
        $response = [
            'data'=>$data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }
}
