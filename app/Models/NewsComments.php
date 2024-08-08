<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class NewsComments extends Model
{
    use HasFactory;

    protected $table = 'news_comments';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['news_id','uid','comments','extra_field','status'];
}
