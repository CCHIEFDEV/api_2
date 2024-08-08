<?php

namespace App\Http\Controllers\v1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\News;
use App\Models\Categories;
use App\Models\User;
use App\Models\Flush;
use App\Models\NewsLikes;
use App\Models\SavedNews;
use App\Models\Cities;
use Validator;
use DB;

class NewsController extends Controller
{
    public function save(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'cate_id' => 'required',
            'city_id' => 'required',
            'sub_cate_id' => 'required',
            'author_id' => 'required',
            'title' => 'required',
            'url_slugs' => 'required',
            'cover' => 'required',
            'video_url' => 'required',
            'content' => 'required',
            'short_descriptions' => 'required',
            'likes' => 'required',
            'comments' => 'required',
            'share_content' => 'required',
            'translations' => 'required',
            'seo_tags' => 'required',
            'status' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.',
                $validator->errors(),
                'status' => 500
            ];
            return response()->json($response, 404);
        }

        $data = News::create($request->all());
        if (is_null($data)) {
            $response = [
                'data' => $data,
                'message' => 'error',
                'status' => 500,
            ];
            return response()->json($response, 200);
        }
        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getById(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.',
                $validator->errors(),
                'status' => 500
            ];
            return response()->json($response, 404);
        }

        $data = News::find($request->id);

        if (is_null($data)) {
            $response = [
                'success' => false,
                'message' => 'Data not found.',
                'status' => 404
            ];
            return response()->json($response, 404);
        }

        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function update(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.',
                $validator->errors(),
                'status' => 500
            ];
            return response()->json($response, 404);
        }
        $data = News::find($request->id)->update($request->all());

        if (is_null($data)) {
            $response = [
                'success' => false,
                'message' => 'Data not found.',
                'status' => 404
            ];
            return response()->json($response, 404);
        }
        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function delete(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'id' => 'required',
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.',
                $validator->errors(),
                'status' => 500
            ];
            return response()->json($response, 404);
        }
        $data = News::find($request->id);
        if ($data) {
            $data->delete();
            $response = [
                'data' => $data,
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

    public function getAll()
    {
        $data = DB::table('news')->select(
            'news.id as id',
            'news.author_id as author_id',
            'news.cate_id as cate_id',
            'news.city_id as city_id',
            'news.comments as comments',
            'news.cover as cover',
            'news.created_at as created_at',
            'news.likes as likes',
            'news.sub_cate_id as sub_cate_id',
            'news.status as status',
            'news.title as title',
            'news.updated_at as updated_at',
            'news.meta_url as meta_url',
            'news.meta_code as meta_code',
            'categories.name as cate_name',
            'cities.name as city_name',
            'users.first_name as author_first_name',
            'users.last_name as author_last_name',
            'news.translations as translations'
        )
            ->join('categories', 'news.cate_id', 'categories.id')
            ->join('cities', 'news.city_id', 'cities.id')
            ->join('users', 'news.author_id', 'users.id')
            ->orderBy('news.id', 'desc')
            ->get();
        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getActiveNews(Request $request)
    {
        $data = News::where('status', 1)->get();
        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getByCate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'limit' => 'required',
            'id' => 'required'
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.',
                $validator->errors(),
                'status' => 500
            ];
            return response()->json($response, 404);
        }
        $matchThese = ['news.status' => 1, 'news.cate_id' => $request->id];
        $data = DB::table('news')
            ->select(
                'news.id as id',
                'news.cate_id as cate_id',
                'news.comments as comments',
                'news.content as content',
                'news.cover as cover',
                'news.created_at',
                'news.extra_field as extra_field',
                'news.likes as likes',
                'news.share_content as share_content',
                'news.short_descriptions as short_descriptions',
                'news.url_slugs as url_slugs',
                'news.status as status',
                'news.title as title',
                'news.translations as translations',
                'news.video_url as video_url',
                'news.meta_url as meta_url',
                'news.meta_code as meta_code',
                'categories.name as cate_name',
                'categories.translations as cate_translations',
                'categories.title_color as title_color',
                'cities.name as city_name',
                'users.first_name as author_first_name',
                'users.last_name as author_last_name'
            )
            ->join('categories', 'news.cate_id', '=', 'categories.id')
            ->join('cities', 'news.city_id', '=', 'cities.id')
            ->join('users', 'news.author_id', '=', 'users.id')
            ->where($matchThese)
            ->orderBy('news.id', 'desc')
            ->limit($request->limit)
            ->get();
        foreach ($data as $loop) {
            if ($request->uid) {
                $temp = NewsLikes::where(['uid' => $request->uid, 'news_id' => $loop->id])->first();
                $tempSaved = SavedNews::where(['uid' => $request->uid, 'news_id' => $loop->id])->first();
                if (isset($temp) && $temp->id) {
                    $loop->haveLiked = true;
                } else {
                    $loop->haveLiked = false;
                }

                if (isset($tempSaved) && $tempSaved->id) {
                    $loop->haveSaved = true;
                } else {
                    $loop->haveSaved = false;
                }
            } else {
                $loop->haveLiked = false;
                $loop->haveSaved = false;
            }
        }
        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getByNewsId(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'id' => 'required'
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.',
                $validator->errors(),
                'status' => 500
            ];
            return response()->json($response, 404);
        }
        $matchThese = ['news.id' => $request->id];
        $data = DB::table('news')
            ->select(
                'news.id as id',
                'news.cate_id as cate_id',
                'news.comments as comments',
                'news.content as content',
                'news.cover as cover',
                'news.created_at',
                'news.extra_field as extra_field',
                'news.likes as likes',
                'news.share_content as share_content',
                'news.short_descriptions as short_descriptions',
                'news.url_slugs as url_slugs',
                'news.status as status',
                'news.title as title',
                'news.translations as translations',
                'news.video_url as video_url',
                'news.meta_url as meta_url',
                'news.meta_code as meta_code',
                'categories.name as cate_name',
                'categories.translations as cate_translations',
                'categories.title_color as title_color',
                'cities.name as city_name',
                'users.first_name as author_first_name',
                'users.last_name as author_last_name'
            )
            ->join('categories', 'news.cate_id', '=', 'categories.id')
            ->join('cities', 'news.city_id', '=', 'cities.id')
            ->join('users', 'news.author_id', '=', 'users.id')
            ->where($matchThese)
            ->first();
        if ($request->uid) {
            $temp = NewsLikes::where(['uid' => $request->uid, 'news_id' => $data->id])->first();
            $tempSaved = SavedNews::where(['uid' => $request->uid, 'news_id' => $data->id])->first();
            if (isset($temp) && $temp->id) {
                $data->haveLiked = true;
            } else {
                $data->haveLiked = false;
            }

            if (isset($tempSaved) && $tempSaved->id) {
                $data->haveSaved = true;
            } else {
                $data->haveSaved = false;
            }
        } else {
            $data->haveLiked = false;
            $data->haveSaved = false;
        }
        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getRelate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'id' => 'required'
        ]);
        if ($validator->fails()) {
            $response = [
                'success' => false,
                'message' => 'Validation Error.',
                $validator->errors(),
                'status' => 500
            ];
            return response()->json($response, 404);
        }
        $matchThese = ['news.status' => 1, 'news.cate_id' => $request->id];
        $data = DB::table('news')
            ->select(
                'news.id as id',
                'news.cate_id as cate_id',
                'news.comments as comments',
                'news.content as content',
                'news.cover as cover',
                'news.created_at',
                'news.extra_field as extra_field',
                'news.likes as likes',
                'news.share_content as share_content',
                'news.short_descriptions as short_descriptions',
                'news.url_slugs as url_slugs',
                'news.status as status',
                'news.title as title',
                'news.translations as translations',
                'news.video_url as video_url',
                'news.meta_url as meta_url',
                'news.meta_code as meta_code',
                'categories.name as cate_name',
                'categories.translations as cate_translations',
                'categories.title_color as title_color',
                'cities.name as city_name',
                'users.first_name as author_first_name',
                'users.last_name as author_last_name'
            )
            ->join('categories', 'news.cate_id', '=', 'categories.id')
            ->join('cities', 'news.city_id', '=', 'cities.id')
            ->join('users', 'news.author_id', '=', 'users.id')
            ->where($matchThese)
            ->orderBy('news.id', 'desc')
            ->limit(10)
            ->get();
        foreach ($data as $loop) {
            if ($request->uid) {
                $temp = NewsLikes::where(['uid' => $request->uid, 'news_id' => $loop->id])->first();
                $tempSaved = SavedNews::where(['uid' => $request->uid, 'news_id' => $loop->id])->first();
                if (isset($temp) && $temp->id) {
                    $loop->haveLiked = true;
                } else {
                    $loop->haveLiked = false;
                }

                if (isset($tempSaved) && $tempSaved->id) {
                    $loop->haveSaved = true;
                } else {
                    $loop->haveSaved = false;
                }
            } else {
                $loop->haveLiked = false;
                $loop->haveSaved = false;
            }
        }
        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function searchQuery(Request $request)
    {
        $str = "";
        if ($request->has('param')) {
            $str = $request->param;
        }

        $news = News::select('id', 'title', 'cover', 'url_slugs', 'translations', 'video_url')->where('status', 1)->where('title', 'like', '%' . $str . '%')->orderBy('id', 'asc')->limit(5)->get();

        $response = [
            'news' => $news,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getVideoNews(Request $request)
    {
        $data = DB::table('news')
            ->select(
                'news.id as id',
                'news.cate_id as cate_id',
                'news.comments as comments',
                'news.content as content',
                'news.cover as cover',
                'news.created_at',
                'news.extra_field as extra_field',
                'news.likes as likes',
                'news.share_content as share_content',
                'news.short_descriptions as short_descriptions',
                'news.url_slugs as url_slugs',
                'news.status as status',
                'news.title as title',
                'news.translations as translations',
                'news.video_url as video_url',
                'news.meta_url as meta_url',
                'news.meta_code as meta_code',
                'categories.name as cate_name',
                'categories.translations as cate_translations',
                'categories.title_color as title_color',
                'cities.name as city_name',
                'users.first_name as author_first_name',
                'users.last_name as author_last_name'
            )
            ->join('categories', 'news.cate_id', '=', 'categories.id')
            ->join('cities', 'news.city_id', '=', 'cities.id')
            ->join('users', 'news.author_id', '=', 'users.id')
            ->where('news.status', 1)
            ->where('news.video_url', '!=', 'NA')
            ->orderBy('news.id', 'desc')
            ->get();

        $response = [
            'data' => $data,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }

    public function getTopNews(Request $request)
    {
        $data = Flush::where('key', 'web-settings')->first();
        if ($data) {
            $value = json_decode($data['value']);
            $bannersId = explode(',', $value->banners);
            $newsId = explode(',', $value->news);
            $data['banners'] = News::WhereIn('id', $bannersId)->get();
            $data['news'] = DB::table('news')
                ->select(
                    'news.id as id',
                    'news.cate_id as cate_id',
                    'news.comments as comments',
                    'news.content as content',
                    'news.cover as cover',
                    'news.created_at',
                    'news.extra_field as extra_field',
                    'news.likes as likes',
                    'news.share_content as share_content',
                    'news.short_descriptions as short_descriptions',
                    'news.url_slugs as url_slugs',
                    'news.status as status',
                    'news.title as title',
                    'news.translations as translations',
                    'news.video_url as video_url',
                    'news.meta_url as meta_url',
                    'news.meta_code as meta_code',
                    'categories.name as cate_name',
                    'categories.translations as cate_translations',
                    'categories.title_color as title_color',
                    'cities.name as city_name',
                    'users.first_name as author_first_name',
                    'users.last_name as author_last_name'
                )
                ->join('categories', 'news.cate_id', '=', 'categories.id')
                ->join('cities', 'news.city_id', '=', 'cities.id')
                ->join('users', 'news.author_id', '=', 'users.id')
                ->WhereIn('news.id', $newsId)
                ->orderBy('news.id', 'desc')
                ->get();
            // $data['news'] = DB::table('news')
            // ->select('news.id as id','news.cate_id as cate_id','news.comments as comments','news.content as content','news.cover as cover',
            // 'news.created_at','news.extra_fields as extra_fields','news.likes as likes','news.share_content as share_content','news.short_description as short_description',
            // 'news.slugs as slugs','news.status as status','news.title as title','news.translations as translations','news.type as type','news.videoUrl as videoUrl',
            // 'categories.name as cate_name','categories.translations as cate_translations','categories.title_color as title_color')
            // ->join('categories', 'news.cate_id', '=', 'categories.id')
            // ->orderBy('news.id','desc')
            // ->WhereIn('news.id',$newsId)
            // ->get();

            foreach ($data['news'] as $loop) {
                if ($request->uid) {
                    $temp = NewsLikes::where(['uid' => $request->uid, 'news_id' => $loop->id])->first();
                    $tempSaved = SavedNews::where(['uid' => $request->uid, 'news_id' => $loop->id])->first();
                    if (isset($temp) && $temp->id) {
                        $loop->haveLiked = true;
                    } else {
                        $loop->haveLiked = false;
                    }

                    if (isset($tempSaved) && $tempSaved->id) {
                        $loop->haveSaved = true;
                    } else {
                        $loop->haveSaved = false;
                    }
                } else {
                    $loop->haveLiked = false;
                    $loop->haveSaved = false;
                }
            }
            $response = [
                'saved' => $data,
                'success' => true,
                'status' => 200,
            ];
            return response()->json($response, 200);
        }

        $response = [
            'saved' => [],
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);

    }

    public function getDashboard(Request $request)
    {
        $news = News::count();
        $categories = Categories::count();
        $users = User::count();
        $cities = Cities::count();
        $data = DB::table('news')->select(
            'news.id as id',
            'news.author_id as author_id',
            'news.cate_id as cate_id',
            'news.city_id as city_id',
            'news.comments as comments',
            'news.cover as cover',
            'news.created_at as created_at',
            'news.likes as likes',
            'news.sub_cate_id as sub_cate_id',
            'news.status as status',
            'news.title as title',
            'news.updated_at as updated_at',
            'news.meta_url as meta_url',
            'news.meta_code as meta_code',
            'categories.name as cate_name',
            'cities.name as city_name',
            'users.first_name as author_first_name',
            'users.last_name as author_last_name',
            'news.translations as translations'
        )
            ->join('categories', 'news.cate_id', 'categories.id')
            ->join('cities', 'news.city_id', 'cities.id')
            ->join('users', 'news.author_id', 'users.id')
            ->limit(10)
            ->orderBy('id', 'desc')
            ->get();
        $response = [
            'data' => $data,
            'news' => $news,
            'categories' => $categories,
            'user' => $users,
            'cities' => $cities,
            'success' => true,
            'status' => 200,
        ];
        return response()->json($response, 200);
    }
}
