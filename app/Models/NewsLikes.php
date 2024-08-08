<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class NewsLikes extends Model
{
    use HasFactory;

    protected $table = 'news_likes';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['news_id','uid','extra_field','status'];
}
