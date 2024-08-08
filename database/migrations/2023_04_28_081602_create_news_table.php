<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('news', function (Blueprint $table) {
            $table->id();
            $table->integer('cate_id');
            $table->integer('city_id');
            $table->integer('sub_cate_id')->default(0);
            $table->integer('author_id');
            $table->string('title');
            $table->text('url_slugs');
            $table->string('cover');
            $table->string('video_url')->nullable();
            $table->text('content');
            $table->text('short_descriptions');
            $table->integer('likes')->default(0);
            $table->integer('comments')->default(0);
            $table->text('share_content')->nullable();
            $table->text('translations')->nullable();
            $table->text('seo_tags');
            $table->text('extra_field')->nullable();
            $table->tinyInteger('status')->default(1);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('news');
    }
};
