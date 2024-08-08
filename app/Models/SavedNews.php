<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SavedNews extends Model
{
    use HasFactory;

    protected $table = 'saved_news';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['news_id','uid','extra_field','status'];
}
